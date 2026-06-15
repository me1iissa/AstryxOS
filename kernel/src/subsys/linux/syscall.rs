//! Linux x86_64 Compatibility Syscall Dispatch
//!
//! Contains `dispatch()` — the Linux ABI syscall dispatcher — and all
//! Linux-specific helper functions (sys_read_linux, sys_write_linux, …).
//!
//! Shared helpers (sys_mmap, sys_fork, sys_exec, …) remain in
//! `kernel/src/syscall/mod.rs` as `pub(crate)` items and are accessed via
//! `crate::syscall::`.  Per-process fd-type helpers (is_pipe_fd, …) likewise.
//!
//! # Phase 0.2 boundary
//! This module is the physical home of the Linux dispatch body; the forwarding
//! stub in `crate::subsys::linux::dispatch()` delegates to `self::dispatch()`.

extern crate alloc;

use alloc::vec::Vec;

// ── memfd sealing side-table ─────────────────────────────────────────────────
//
// Tracks which inodes were created with MFD_ALLOW_SEALING and their current
// seal mask.  Per memfd_create(2) and fcntl(2): an inode without sealing
// capability must return -EPERM on F_ADD_SEALS; once F_SEAL_SEAL is added no
// further seals may be applied.
//
// Entry: (inode_number, seal_mask).  Absent = not sealing-capable.
// Seal constants (same bit definitions as <linux/memfd.h>):
//   F_SEAL_SEAL         = 0x0001
//   F_SEAL_SHRINK       = 0x0002
//   F_SEAL_GROW         = 0x0004
//   F_SEAL_WRITE        = 0x0008
//   F_SEAL_FUTURE_WRITE = 0x0010
const F_SEAL_SEAL:         u32 = 0x0001;
const F_SEAL_SHRINK:       u32 = 0x0002;
const F_SEAL_GROW:         u32 = 0x0004;
const F_SEAL_WRITE:        u32 = 0x0008;
const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
const F_SEAL_ALL_VALID:    u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

static MEMFD_SEALS: spin::Mutex<Vec<(u64, u32)>> = spin::Mutex::new(Vec::new());

/// Register `inode` as sealing-capable with an initial seal mask of 0.
/// Called from sys_memfd_create when MFD_ALLOW_SEALING is set.
fn memfd_seals_register(inode: u64) {
    let mut seals = MEMFD_SEALS.lock();
    // Guard against double-registration (shouldn't happen, but be safe).
    if !seals.iter().any(|(ino, _)| *ino == inode) {
        seals.push((inode, 0));
    }
}

/// Look up the current seal mask for `inode`.
/// Returns `Some(mask)` if sealing-capable, `None` otherwise.
fn memfd_seals_get(inode: u64) -> Option<u32> {
    MEMFD_SEALS.lock().iter().find(|(ino, _)| *ino == inode).map(|(_, m)| *m)
}

/// Build the per-OBJECT watch set for a poll/select/epoll parker — the
/// intra-class herd collapse.  Returns `(class_mask, objects)`:
///
/// * `class_mask` — the wake-on-CLASS bitset: the cross-cutting always-wake
///   classes (`Other`, `SignalInject`), plus the source bit of any watched fd
///   whose backing object could not be pinned to a concrete id (unknown /
///   regular-file / nested-epoll / raced fd, OR a resolver that returned the
///   `u64::MAX` not-found sentinel).  A source in `class_mask` wakes the parker
///   on ANY edge of that class — the conservative, never-under-wake fallback.
/// * `objects` — the concrete `(source, object_id)` pins for fds that DID
///   resolve to a stable object.  A targeted `ring_poll_bell_for_obj(S, id)`
///   wakes this parker only when `(S, id)` is in this list.
///
/// CRITICAL (no under-wake): a source class is recorded in EXACTLY ONE place per
/// fd — `objects` when pinnable, else `class_mask`.  But the same source class
/// can appear in BOTH across DIFFERENT fds (e.g. one AF_UNIX fd pins object 5
/// while an unclassifiable fd forces UnixWrite into `class_mask`); that is
/// correct and still a superset — `class_mask` then makes EVERY UnixWrite edge
/// wake this parker, which over-wakes but never under-wakes.  The fd-type
/// dispatch order matches the `select(2)`/`poll` readiness dispatch (unix
/// BEFORE the generic socket flag) so a unix socket is never misclassified
/// as inet-only and never drops its UnixWrite/UnixRead/UnixShutdown wakes.
///
/// AF_UNIX fds subscribe to THREE classes (`UnixWrite` data-in, `UnixRead` peer
/// write-space, `UnixShutdown` half-close/connect).  The object id is the SAME
/// for all three (the socket's own id), so all three are pinned to it — a
/// targeted ring of any of the three on that object reaches this parker.
fn bell_watch_for_fds(
    pid: u64,
    fds: impl Iterator<Item = usize>,
) -> (u32, alloc::vec::Vec<crate::ipc::waitlist::ObjWatch>) {
    use crate::ipc::waitlist::{ObjWatch, PollBellSource as S, BELL_MASK_ALL, OBJECT_ID_NONE};
    // Cross-cutting always-wake classes (must reach every parker).
    let mut class_mask = (1u32 << (S::Other as u32)) | (1u32 << (S::SignalInject as u32));
    let mut objects: alloc::vec::Vec<ObjWatch> = alloc::vec::Vec::new();
    // Helper: pin `(source, id)` if `id` resolved, else fall back to wake-on-class.
    let mut pin = |objects: &mut alloc::vec::Vec<ObjWatch>,
                   class_mask: &mut u32,
                   source: S,
                   id: u64| {
        if id == OBJECT_ID_NONE {
            *class_mask |= 1u32 << (source as u32); // not-found → wake-on-class
        } else {
            objects.push(ObjWatch { source, object_id: id });
        }
    };
    for fd in fds {
        // Dispatch order matches select/poll readiness (unix BEFORE the generic
        // socket flag).  Each branch either pins a concrete object or — for an
        // unclassifiable fd — saturates `class_mask` to wake-on-everything.
        if crate::syscall::is_pipe_fd(pid, fd) {
            pin(&mut objects, &mut class_mask, S::Pipe,
                crate::syscall::get_pipe_id(pid, fd));
        } else if crate::syscall::is_eventfd_fd(pid, fd) {
            pin(&mut objects, &mut class_mask, S::Eventfd,
                crate::syscall::get_eventfd_id(pid, fd));
        } else if crate::syscall::is_unix_socket_fd(pid, fd) {
            let id = crate::syscall::get_unix_socket_id(pid, fd);
            pin(&mut objects, &mut class_mask, S::UnixWrite, id);
            pin(&mut objects, &mut class_mask, S::UnixRead, id);
            pin(&mut objects, &mut class_mask, S::UnixShutdown, id);
        } else if crate::syscall::is_socket_fd(pid, fd) {
            pin(&mut objects, &mut class_mask, S::InetRx,
                crate::syscall::get_socket_id(pid, fd));
        } else if crate::syscall::is_timerfd_fd(pid, fd) {
            // timerfd fires from an ISR with no id in scope (class-only ring), so
            // pin would never match; subscribe by class instead.
            class_mask |= 1u32 << (S::Timerfd as u32);
        } else if crate::syscall::is_signalfd_fd(pid, fd) {
            class_mask |=
                (1u32 << (S::Signalfd as u32)) | (1u32 << (S::SignalInject as u32));
        } else if crate::syscall::is_inotify_fd(pid, fd) {
            pin(&mut objects, &mut class_mask, S::Inotify,
                crate::syscall::get_inotify_id(pid, fd));
        } else {
            // Unknown / regular-file / nested-epoll / raced fd: wake on EVERY
            // source.  Saturated mask means objects no longer matter.
            class_mask = BELL_MASK_ALL;
            objects.clear();
            return (class_mask, objects);
        }
    }
    (class_mask, objects)
}

/// Add seals to `inode`.  Returns 0 on success, -EPERM/-EINVAL on error.
fn memfd_seals_add(inode: u64, new_seals: u32) -> i64 {
    if new_seals & !F_SEAL_ALL_VALID != 0 {
        return -22; // EINVAL — unknown seal bits
    }
    let mut seals = MEMFD_SEALS.lock();
    match seals.iter_mut().find(|(ino, _)| *ino == inode) {
        None => -1, // Not sealing-capable (caller converts to -EPERM)
        Some((_, mask)) => {
            if *mask & F_SEAL_SEAL != 0 {
                return -1; // F_SEAL_SEAL is set — no further seals allowed (caller converts to -EPERM)
            }
            *mask |= new_seals;
            0
        }
    }
}

// ===== Linux Syscall ABI Compatibility Layer ================================
//
// musl-libc (and other Linux binaries) use Linux x86_64 syscall numbers which
// differ from AstryxOS's custom numbering (0–49). This layer translates Linux
// numbers to AstryxOS handlers, adding Linux-specific syscalls needed for a
// static musl-linked "hello world" (printf + file I/O + malloc).

// ─── VFORK/CANARY diagnostic ────────────────────────────────────────────────
//
// Per POSIX.1-2017 §3.378 ("vfork was deprecated in POSIX.1-2008 because it
// is impossible to use safely") and the Linux clone(2) man page (Linux
// man-pages 6.7, §"CLONE_VM"), a CLONE_VM child shares the parent's address
// space.  Linux's classical implementation blocks the parent and runs the
// child on its OWN stack region; AstryxOS currently runs the child on the
// parent's user RSP when the caller did not pass a `new_stack` argument
// (see `fork_process_share_vm` in proc/mod.rs).  That makes any RSP-relative
// store by the child visible to the parent at wake-up.
//
// The ELF gABI §6 stack-protector ("-fstack-protector") layout places the
// per-frame canary at `[rbp - 8]` for functions whose prologue contains
// `mov rax, fs:0x28; mov [rbp-8], rax`.  If the child's local-variable
// spills land on top of a libxul caller's `[rbp-8]` slot, the canary mismatch
// at function epilogue triggers `__stack_chk_fail` → musl's `HLT; RET`
// abort sequence (a #GP from CPL3).
//
// `vfork_canary_snapshot` records the parent's IA32_FS_BASE MSR (Intel SDM
// Vol. 3A §3.4.4.1), the user-stack window above the parent's RSP at vfork
// entry, and the canary tag fetched via `fs:0x28` (musl's __stack_chk_guard
// location).  The pre-block and post-wake snapshots together let downstream
// analysis decide whether the child overwrote parent state during the
// vfork window — without applying any fix.
//
// ─── Wave 14 (R-A): user-RBP snapshot ────────────────────────────────────
//
// PR #407 (Wave 12) verified slot-14 (saved user_rsp at `kstack_top - 8`) is
// bit-stable across `schedule()` on the vfork-wake path.  PR #408 (Wave 13)
// falsified Mechanism D phys-aliasing on the user-canary VA.  The next
// hypothesis (R-A per PR #409 tech-lead cross-walk) is that the parent's
// user-mode RBP (saved at `kstack_top - 32`, frame slot 11 per
// `syscall_entry` save layout in `kernel/src/syscall/mod.rs`) drifts across
// the vfork-wake `schedule()`.  Per SysV AMD64 ABI §3.4.5.2 (frame-pointer
// convention) RBP must be preserved across calls; per Intel SDM Vol. 3A §6
// (interrupt/syscall return) IRETQ/SYSRET restore the saved frame verbatim,
// so any drift across the syscall window is a kernel-side bug.
//
// If the parent's user-RBP differs between `pre_block` and `post_wake`, the
// SSP epilogue's `XOR [rbp-8], rax` reads a different VA than the prologue's
// store and produces the observed canary mismatch — and R-A becomes the
// dispositive lead.  If RBP is stable, R-A is falsified and the next
// dispatch (R-B per PR #409) examines FPO calling-convention skew.
// ─── Wave 14 R-A: tiny pre-cache for RBP-drift diff ───────────────────────
//
// `vfork_canary_snapshot` is stateless, so to emit a derived `rbp_diff`
// field at the post-wake call we cache the pre-block RBP value here.  Keyed
// on `parent_tid` (unique per in-flight vfork; bounded by `MAX_INFLIGHT`).
// Lockless reads/writes via `AtomicU64`; sized for ≤16 concurrent vfork
// parents which is well above any observed live count.  No allocation, no
// teardown — entries are overwritten in place.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
const MAX_INFLIGHT: usize = 16;
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
static RBP_PRE_CACHE: [(core::sync::atomic::AtomicU64, core::sync::atomic::AtomicU64); MAX_INFLIGHT] = [
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
    (core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)),
];

/// Stash the pre-block RBP for a vfork parent.  Overwrites the slot keyed
/// on `parent_tid` if present, else claims an empty slot (key==0).  Falls
/// back to slot 0 on full ring — only loses precision for unrealistic
/// concurrent-vfork counts.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
fn rbp_pre_cache_store(parent_tid: u64, rbp: u64) {
    use core::sync::atomic::Ordering;
    for (k, v) in RBP_PRE_CACHE.iter() {
        let cur = k.load(Ordering::Relaxed);
        if cur == parent_tid || cur == 0 {
            k.store(parent_tid, Ordering::Relaxed);
            v.store(rbp, Ordering::Relaxed);
            return;
        }
    }
    RBP_PRE_CACHE[0].0.store(parent_tid, Ordering::Relaxed);
    RBP_PRE_CACHE[0].1.store(rbp, Ordering::Relaxed);
}

/// Look up the pre-block RBP for `parent_tid`.  Returns `None` if no pre
/// snapshot has been stored (e.g. on a post-wake call without a matching
/// pre-block).  Does NOT clear the slot — re-vfork by the same TID
/// overwrites in-place.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
fn rbp_pre_cache_load(parent_tid: u64) -> Option<u64> {
    use core::sync::atomic::Ordering;
    for (k, v) in RBP_PRE_CACHE.iter() {
        if k.load(Ordering::Relaxed) == parent_tid {
            return Some(v.load(Ordering::Relaxed));
        }
    }
    None
}

#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
fn vfork_canary_snapshot(label: &str, pid: u32, parent_tid: u64) {
    use core::fmt::Write;

    // Parent's user RSP at syscall entry lives at `kstack_top - 8` (see
    // `syscall_entry` save layout in syscall/mod.rs).  Look up via
    // THREAD_TABLE so we work both pre-block (still in the parent's syscall
    // frame) and post-wake (same frame, since `schedule()` returns to it).
    let kstack_top = {
        let threads = crate::proc::THREAD_TABLE.lock();
        threads.iter().find(|t| t.tid == parent_tid)
            .map(|t| t.kernel_stack_base + t.kernel_stack_size)
            .unwrap_or(0)
    };
    if kstack_top == 0 {
        crate::serial_println!(
            "[VFORK/CANARY] {} pid={} parent_tid={} state=no_kstack",
            label, pid, parent_tid);
        return;
    }
    let parent_user_rsp = unsafe { *((kstack_top - 8) as *const u64) };
    // Wave 14 R-A: saved user_rbp lives at `kstack_top - 32` (frame slot
    // 11 per `syscall_entry` layout: rdi, rsi, rdx, r8, r9, r10, r15, r14,
    // r13, r12, rbx, rbp, r11, rcx, user_rsp — RBP is the 12th save, four
    // qwords from the top).  Read from the same kernel-stack frame as the
    // user_rsp read above; same SAFETY justification.
    let parent_user_rbp = unsafe { *((kstack_top - 32) as *const u64) };

    // FS_BASE MSR (Intel SDM Vol. 3A §3.4.4.1, IA32_FS_BASE = 0xC000_0100).
    // Captures the live FS_BASE for the currently-running thread, which —
    // when this helper is called from the parent's syscall body — is the
    // parent's TLS base.
    let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };

    // TLS canary tag at `fs:0x28` per ELF gABI stack-protector §6.  The
    // TLS block lives at fs_base[0..]; the canary tag sits at offset 0x28
    // (`__stack_chk_guard`).  We snapshot it via the kernel-visible
    // virtual address (fs_base + 0x28) under SMAP brackets.
    let canary_addr = fs_base.wrapping_add(0x28);
    let fs28: Option<u64> = if crate::syscall::validate_user_ptr(canary_addr, 8) {
        unsafe { crate::syscall::user_read_u64(canary_addr) }
    } else {
        None
    };

    // Window above the parent's user RSP.  Empirically the #GP at
    // `__stack_chk_fail` fires from a libxul `posix_spawn` caller frame
    // ~0x1d60 bytes above the parent's RSP at vfork, so an 8 KiB window
    // covers the entire stack region between vfork-entry and the
    // SSP-failing caller frame.  Probe slots are chosen to bracket
    // plausible `[rbp-8]` canary locations for libxul-shaped callers.
    let win_base = parent_user_rsp;
    let win_size: usize = 0x2000;
    let mut stack_bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    if win_base != 0 && crate::syscall::validate_user_ptr(win_base, win_size) {
        if let Some(buf) = unsafe { crate::syscall::user_slice_snapshot(win_base, win_size) } {
            stack_bytes = buf;
        }
    }

    let read_slot = |off: usize| -> u64 {
        if stack_bytes.len() >= off + 8 {
            u64::from_le_bytes([
                stack_bytes[off],     stack_bytes[off + 1], stack_bytes[off + 2], stack_bytes[off + 3],
                stack_bytes[off + 4], stack_bytes[off + 5], stack_bytes[off + 6], stack_bytes[off + 7],
            ])
        } else { 0 }
    };
    let slot_1d8  = read_slot(0x1d8);
    let slot_1e0  = read_slot(0x1e0);
    let slot_d58  = read_slot(0xd58);
    let slot_1d58 = read_slot(0x1d58);
    let slot_1d60 = read_slot(0x1d60);

    // Fletcher-32 over the whole window (no_std friendly; stable for diffing).
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    for b in &stack_bytes {
        sum1 = (sum1.wrapping_add(*b as u32)) % 65535;
        sum2 = (sum2.wrapping_add(sum1)) % 65535;
    }
    let win_crc: u32 = (sum2 << 16) | sum1;

    // Read the first qword at fs_base.  Per the x86_64 psABI §3.4.6
    // "Thread-Local Storage" (TLS Variant II) the TCB starts at FS_BASE
    // and its first word is the TCB self-pointer.  If FS_BASE doesn't
    // point at a valid TCB the read either faults (None) or returns a
    // value that doesn't equal FS_BASE — both informative.
    let tcb_self: Option<u64> = if crate::syscall::validate_user_ptr(fs_base, 8) {
        unsafe { crate::syscall::user_read_u64(fs_base) }
    } else {
        None
    };

    // Wave 14 R-A: compute rbp_diff for post-wake calls.  On a pre_block
    // label the diff is reported as "pre" (the field is informational only
    // at pre); on a post_wake label, look up the matching pre-block RBP
    // and report `same` / `drift=<delta>` / `nopre` (if cache miss).
    let rbp_diff_str: alloc::string::String = if label.starts_with("pre_block") {
        rbp_pre_cache_store(parent_tid, parent_user_rbp);
        alloc::string::String::from("pre")
    } else if label.starts_with("post_wake") {
        match rbp_pre_cache_load(parent_tid) {
            None => alloc::string::String::from("nopre"),
            Some(rbp_pre) if rbp_pre == parent_user_rbp => alloc::string::String::from("same"),
            Some(rbp_pre) => {
                // Signed delta = post - pre, formatted as hex with sign.
                let delta = (parent_user_rbp as i64).wrapping_sub(rbp_pre as i64);
                if delta >= 0 {
                    alloc::format!("drift=+{:#x}_pre={:#x}", delta as u64, rbp_pre)
                } else {
                    alloc::format!("drift=-{:#x}_pre={:#x}", (-delta) as u64, rbp_pre)
                }
            }
        }
    } else {
        alloc::string::String::from("n/a")
    };

    let mut line = alloc::string::String::with_capacity(448);
    let _ = write!(&mut line,
        "[VFORK/CANARY] {} pid={} parent_tid={} \
         fs_base={:#x} fs_28={} tcb_self={} \
         user_rsp={:#x} rsp_slot14={:#x} rbp_slot11={:#x} rbp_diff={} \
         s_1d8={:#x} s_1e0={:#x} s_d58={:#x} s_1d58={:#x} s_1d60={:#x} \
         win_bytes={} win_crc={:#x}",
        label, pid, parent_tid,
        fs_base,
        fs28.map(|v| alloc::format!("{:#x}", v)).unwrap_or_else(|| alloc::string::String::from("?")),
        tcb_self.map(|v| alloc::format!("{:#x}", v)).unwrap_or_else(|| alloc::string::String::from("?")),
        parent_user_rsp, parent_user_rsp, parent_user_rbp, rbp_diff_str,
        slot_1d8, slot_1e0, slot_d58, slot_1d58, slot_1d60,
        stack_bytes.len(), win_crc);
    crate::serial_println!("{}", line);
}

#[cfg(not(any(feature = "firefox-test-core", feature = "test-mode")))]
fn vfork_canary_snapshot(_label: &str, _pid: u32, _parent_tid: u64) {}

/// Check whether the current process uses the Linux syscall ABI.
///
/// Reads the per-CPU lockless PID first — fast path, correct whenever a
/// user thread is currently scheduled.  Falls back to a kernel-stack-top
/// walk (see slow path below) for the brief context-switch window when
/// `PER_CPU_CURRENT_PID` reads as 0 but a user syscall is in flight.
pub(crate) fn is_linux_abi() -> bool {
    let pid = crate::proc::current_pid_lockless();
    if pid != 0 {
        // Fast path: PER_CPU_CURRENT_TID is correct.
        let procs = crate::proc::PROCESS_TABLE.lock();
        return procs.iter().find(|p| p.pid == pid).map(|p| {
            p.linux_abi || p.subsystem == crate::win32::SubsystemType::Linux
        }).unwrap_or(false);
    }

    // Slow-path: PER_CPU_CURRENT_TID is stale (scheduling race — the timer
    // preempted a user thread and switched to the idle thread, setting
    // PER_CPU_CURRENT_TID[0]=0, but the SYSCALL was already in-flight for the
    // user thread).
    //
    // crate::syscall::PER_CPU_SYSCALL[cpu].kernel_rsp is set to a user thread's kernel-stack top
    // whenever that thread is scheduled in, and is NOT overwritten when kernel/idle
    // threads run (they have kernel_stack_base==0, so the scheduler skips the
    // set_kernel_rsp call).  We can therefore identify the thread that owns the
    // current SYSCALL by matching its kernel_stack_base+size against kernel_rsp.
    let kstack_top = unsafe { crate::syscall::PER_CPU_SYSCALL[crate::arch::x86_64::apic::cpu_index()].kernel_rsp };
    if kstack_top == 0 {
        return false; // No user thread has been set up on this CPU yet.
    }
    let thread_pid = {
        let threads = crate::proc::THREAD_TABLE.lock();
        threads.iter()
            .find(|t| {
                t.tid != 0
                    && t.kernel_stack_base > 0
                    && t.kernel_stack_base + t.kernel_stack_size == kstack_top
            })
            .map(|t| t.pid)
    };
    if let Some(pid) = thread_pid {
        if pid != 0 {
            let procs = crate::proc::PROCESS_TABLE.lock();
            return procs.iter().find(|p| p.pid == pid).map(|p| {
                p.linux_abi || p.subsystem == crate::win32::SubsystemType::Linux
            }).unwrap_or(false);
        }
    }
    false
}

/// Strict range check for a user pathname pointer.
///
/// Returns `true` iff `ptr` is a non-null low-canonical user-space address.
/// Used as the gate at the head of `sys_open`, `sys_openat`, `sys_access`,
/// `sys_stat` (and other pathname-bearing syscalls) so that an out-of-range
/// pathname is rejected with `-EFAULT` BEFORE `read_cstring_from_user` even
/// runs.  Stricter than `validate_user_ptr(ptr, 1)` because it additionally
/// rejects the non-canonical hole (`[USER_PTR_MAX, KERNEL_VIRT_BASE)`).
///
/// CWE-823 (Out-of-range pointer offset) / CWE-119 (improper memory bounds).
#[inline]
pub(crate) fn user_path_ptr_ok(ptr: u64) -> bool {
    const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;
    ptr != 0 && ptr < USER_PTR_MAX
}

// ── per-CPU C-string staging arena ───────────────────────────────────────────
//
// Pre-#276, `read_cstring_from_user` returned a zero-copy `&[u8]` borrow into
// user memory.  H1-SMAP (PR #276) made it return an owned `Vec<u8>` because
// every dereference of user memory must be wrapped in a STAC/CLAC bracket
// (Intel SDM Vol. 3A §4.6).  The cost of one Vec heap allocation per cstring
// read, multiplied across ~40 call sites and a multi-cstring syscall like
// `mount(2)` (4 cstrings) or `execve(2)` (N argv entries), halved the
// Firefox sustained syscall plateau from sc≈2881 to sc≈1439.
//
// Mitigation: a per-CPU 4-slot ring arena.  Each `read_cstring_from_user`
// call advances a per-CPU slot cursor and writes the user bytes into the
// next slot, then returns a `&'static [u8]` borrow of that slot.  The
// borrow is valid until the same CPU performs `SLOTS_PER_CPU = 4` further
// `read_cstring_from_user` calls — long enough for every observed call
// pattern (`mount` takes 4 cstrings; nothing else takes more) but cheap
// enough to avoid heap allocation entirely.
//
// Safety:
//   - Per-CPU isolation rules out cross-CPU data races on the arena: each
//     CPU only writes its own row of `CSTRING_ARENA` and only ever reads
//     its own row immediately after that write.
//   - On a single CPU, a `read_cstring_from_user` call cannot be reentered
//     from an interrupt — the timer and IPI handlers do not parse user
//     cstrings (per `arch::x86_64::irq` and `arch::x86_64::ipi`).  A NMI
//     handler likewise never touches user memory.  The slot cursor is
//     therefore an ordinary `u8` accessed without atomicity beyond the
//     compiler-fence barrier implicit in raw-pointer writes.
//   - Borrow lifetime is documented as `'static` in the type system, but
//     callers MUST consume the borrow before the same CPU performs four
//     further `read_cstring_from_user` calls.  Every existing call site
//     does (see `dispatch_body` arms in this file): the bytes are
//     immediately converted to `&str` or copied into a `String`, both of
//     which complete before any further user-cstring read on the same CPU.
//
// Sizing: `MAX_CPUS = 16` × `SLOTS_PER_CPU = 4` × `SLOT_SIZE = 4096 B` =
// 256 KiB of `.bss`.  `BOOT_INFO_PHYS_BASE` (see `shared/src/lib.rs`) sits
// several MiB past the current BSS end, so this arena adds no risk of
// clobbering the bootloader handoff page during `_start` BSS zeroing.

const CSTRING_SLOT_SIZE: usize = 4096;
const CSTRING_SLOTS_PER_CPU: usize = 4;

/// Per-CPU cstring staging arena.  Indexed by `[cpu][slot]`.  Writes from
/// each CPU only touch its own row, so SeqCst is unnecessary; the compiler
/// fence implicit in raw-pointer stores plus the per-CPU rule above are
/// sufficient.
static mut CSTRING_ARENA:
    [[[u8; CSTRING_SLOT_SIZE]; CSTRING_SLOTS_PER_CPU]; crate::arch::x86_64::apic::MAX_CPUS] =
    [[[0u8; CSTRING_SLOT_SIZE]; CSTRING_SLOTS_PER_CPU]; crate::arch::x86_64::apic::MAX_CPUS];

/// Per-CPU slot cursor (incrementing).  Modular arithmetic against
/// `CSTRING_SLOTS_PER_CPU` selects the slot.  Single-CPU access pattern
/// (each CPU writes only its own entry); `AtomicU8` is used for cross-CPU
/// safety of the array element itself, not for cursor monotonicity.
static CSTRING_CURSOR:
    [core::sync::atomic::AtomicU8; crate::arch::x86_64::apic::MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    [Z; crate::arch::x86_64::apic::MAX_CPUS]
};

/// Read a null-terminated C string from user memory.
/// Returns a byte slice (excluding the NUL terminator) limited to
/// `CSTRING_SLOT_SIZE = 4096` bytes.
///
/// The returned borrow is backed by a per-CPU staging slot and is valid
/// until the same CPU performs `CSTRING_SLOTS_PER_CPU = 4` further
/// `read_cstring_from_user` calls; see the arena documentation above.
///
/// **Pointer-validation policy** (CWE-823 / CWE-119):  user-mode-originated
/// calls are gated by `user_path_ptr_ok(ptr)` at the dispatch layer (see
/// `dispatch_body` arms 2/4/6/21/257) — those arms return `-14` (EFAULT)
/// before this helper ever runs.  Kernel-internal callers (e.g.
/// `sys_open_test`, in-kernel VFS bring-up) intentionally pass pointers
/// into the kernel-mapped string table to drive the same handler with a
/// known-good path, and rely on the bounded 4096-byte scan here as their
/// only safety constraint.  Splitting validation this way protects every
/// pathname-reading syscall (open, openat, access, stat, statx,
/// readlink, rename, link, mkdir, mount, execve, …) against malicious
/// userspace without breaking the in-kernel test API.
fn read_cstring_from_user(ptr: u64) -> &'static [u8] {
    if ptr == 0 {
        return &[];
    }
    // The user/kernel boundary check is enforced at dispatch (see
    // `user_path_ptr_ok` and the per-syscall dispatch arms in
    // `dispatch_body`).  This helper is also called from kernel-internal
    // glue (`sys_open_test`, in-kernel VFS bring-up) with pointers into
    // the kernel-mapped read-only string table; rejecting those would
    // break the test-runner and early-boot code.  We keep the bounded
    // 4096-byte read as the only defensive limit here.
    //
    // SMAP bracket — every iteration below derefs through `start` which
    // backs the user pointer in the syscall path.  Per Intel SDM Vol. 3A
    // §4.6 the supervisor must hold AC=1 to touch a user page; the
    // UserGuard issues STAC/CLAC accordingly when SMAP is active and
    // collapses to a load + branch otherwise.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    if cpu >= crate::arch::x86_64::apic::MAX_CPUS {
        // Out-of-range CPU index would index past the arena.  In practice
        // `cpu_index()` returns a value < MAX_CPUS for every CPU brought
        // up via `start_aps`; this branch is defensive.
        return &[];
    }
    let slot = (CSTRING_CURSOR[cpu].fetch_add(
        1, core::sync::atomic::Ordering::Relaxed,
    ) as usize) & (CSTRING_SLOTS_PER_CPU - 1);

    // SAFETY: `cpu < MAX_CPUS` and `slot < CSTRING_SLOTS_PER_CPU` so the
    // indexing is in-bounds; the slot is written under a SMAP bracket
    // before being read, and per the arena docs no other CPU writes this
    // row.  We obtain a `*mut u8` to the slot's backing storage so we can
    // copy from user memory directly without an intermediate stack buffer
    // (the previous design's 4 KiB stack + heap allocation).
    let dst: *mut u8 = unsafe {
        let row = &raw mut CSTRING_ARENA[cpu][slot];
        (*row).as_mut_ptr()
    };

    let start = ptr as *const u8;
    let n = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        let mut len = 0usize;
        while len < CSTRING_SLOT_SIZE {
            let b = *start.add(len);
            if b == 0 { break; }
            *dst.add(len) = b;
            len += 1;
        }
        len
    };

    // SAFETY: same indexing-in-bounds argument as above; the slot we just
    // wrote `n` bytes into is now ours to lend as a `&'static [u8]`.  The
    // borrow remains valid until the same CPU advances four further
    // cursor positions, which observation confirms no existing caller
    // does.  Cross-CPU readers cannot reach this slot because their
    // `cpu_index()` differs.
    unsafe {
        let row = &raw const CSTRING_ARENA[cpu][slot];
        core::slice::from_raw_parts((*row).as_ptr(), n)
    }
}

/// Read a null-terminated array of C string pointers (`char *argv[]`) from
/// user memory.  Returns a Vec of owned strings.  Stops at NULL pointer or
/// `ARGV_MAX_ENTRIES = 256` entries.
///
/// # SMAP bracket coalescing
///
/// The naive shape — one [`UserGuard`] per pointer load plus one per
/// cstring scan — costs `N×2` `STAC`+`CLAC` pairs (a single CR4-class CPU
/// state toggle per pair, per Intel SDM Vol. 3A §4.6).  For a typical
/// envp of 30 entries that is 60 STAC/CLAC pairs per `execve(2)` and
/// dominates the syscall cost.
///
/// This helper coalesces to **three** SMAP brackets total, regardless
/// of N (vs the pre-coalesce shape's `2N + 1` brackets):
///
///   * Phase A (one bracket): walk the user pointer array under a
///     single [`UserGuard`], stopping at the first NULL.  The result
///     is `count` pointers in a kernel-side scratch buffer.
///   * Phase B (one bracket): scan every cstring under a single
///     [`UserGuard`] to discover its length (no copy yet).  This
///     lets Phase C size the staging allocation exactly instead of
///     pessimistically reserving the full `ARG_MAX = 128 KiB`.
///   * Phase C (no bracket): allocate a single exact-sized staging
///     buffer.
///   * Phase D (one bracket): copy every cstring body into the
///     staging buffer under a single [`UserGuard`].
///   * Phase E (no bracket): slice the staging buffer into owned
///     `String`s.  All `String::from_utf8_lossy` allocations happen
///     here, never under AC=1 — preserving the SMAP invariant
///     ("AC=1 only while reading user memory") that motivated the
///     pre-coalesce per-iteration bracket shape.
///
/// Bracket budget: 3 STAC/CLAC pairs for any N, vs the pre-coalesce
/// shape's `2N + 1` pairs (one per pointer-array load + one per
/// cstring scan + one final NULL load).  For a typical envp of
/// 30 entries that is 61 STAC/CLAC pairs collapsed to 3.
///
/// Validation discipline is preserved:
///   * The pointer-array range is range-checked via
///     [`crate::syscall::validate_user_ptr`] before Phase A.
///   * Each individual string pointer is range-checked before its
///     cstring scan begins.
///   * A bad pointer aborts the read at that index — the caller sees a
///     truncated argv, matching the existing pre-coalesce behaviour
///     (which silently treated any faulting cstring as empty).
///
/// References:
///   * Intel SDM Vol. 3A §4.6 — SMAP / CR4.SMAP / EFLAGS.AC semantics.
///   * POSIX `execve(2)` — argv / envp pointer-array shape and
///     `ARG_MAX` byte budget.
pub(crate) fn read_user_argv(ptr: u64) -> alloc::vec::Vec<alloc::string::String> {
    /// Max number of argv/envp entries we will copy.  Matches the
    /// pre-coalesce loop bound; chosen well above any realistic argv
    /// or envp (Mozilla content processes peak at ~14 args / ~40 env).
    const ARGV_MAX_ENTRIES: usize = 256;
    /// Max byte budget for the concatenated string bodies — matches the
    /// kernel-side ARG_MAX (POSIX `execve(2)`) and bounds the single
    /// staging allocation.
    const ARG_MAX_BYTES: usize = 128 * 1024;
    /// Per-string scan bound — same as `CSTRING_SLOT_SIZE` so a runaway
    /// (un-NUL-terminated) user string cannot drag the scan past one
    /// page.
    const STRING_SCAN_MAX: usize = CSTRING_SLOT_SIZE;

    let mut result = alloc::vec::Vec::new();
    if ptr == 0 {
        return result;
    }

    // Phase A — validate the pointer-array range.  We pessimistically
    // require `(ARGV_MAX_ENTRIES + 1) × 8` bytes so the array walk in
    // the bounded inner can copy without per-pointer range checks;
    // +1 covers the trailing NULL slot.  If that 2 KiB range is not
    // entirely within user VA, fall back to a progressively tighter
    // probe — the common case (short argv near the top of the user
    // stack) typically maps only enough pages to cover its actual
    // length, not the full 256-entry budget.
    let array_bytes = (ARGV_MAX_ENTRIES + 1).saturating_mul(8);
    if crate::syscall::validate_user_ptr(ptr, array_bytes) {
        return read_user_argv_bounded(ptr, ARGV_MAX_ENTRIES, ARG_MAX_BYTES, STRING_SCAN_MAX);
    }
    // Halve the probe size down to 16 bytes (1 pointer + NULL).  Each
    // step covers a power-of-two prefix; the first one that validates
    // gives us a safe entry count to walk.  16-byte validation guards
    // against an utterly bogus pointer that even one entry would
    // straddle the user/kernel boundary.
    let mut probe = array_bytes / 2;
    while probe >= 16 {
        if crate::syscall::validate_user_ptr(ptr, probe) {
            break;
        }
        probe /= 2;
    }
    if probe < 16 {
        return result;
    }
    read_user_argv_bounded(ptr, probe / 8 - 1, ARG_MAX_BYTES, STRING_SCAN_MAX)
}

/// Bounded inner implementation of [`read_user_argv`].  Separated so the
/// (rare) tight-probe fallback path in the outer wrapper can re-enter
/// with a smaller `max_entries` without duplicating the Phase B / C
/// logic.  Caller has already range-validated the pointer array for
/// `(max_entries + 1) × 8` bytes.
///
/// Bracket budget: exactly **three** SMAP brackets for any argv/envp,
/// regardless of N.  Pre-coalesce shape paid `2N + 1` brackets (one
/// pointer-array load per entry + one cstring scan per entry + one
/// final NULL-terminator load).
fn read_user_argv_bounded(
    ptr: u64,
    max_entries: usize,
    arg_max_bytes: usize,
    string_scan_max: usize,
) -> alloc::vec::Vec<alloc::string::String> {
    let mut result = alloc::vec::Vec::new();

    // Phase A — pointer-array snapshot under ONE SMAP bracket.  We
    // stop at the first NULL (per POSIX `execve(2)` argv terminator)
    // rather than blindly reading `max_entries + 1` slots — the latter
    // is observably wrong because a typical argv lives at the top of
    // the user stack and the pages just above the actual array are not
    // mapped, so the unconditional read faults the kernel even though
    // the user's view is well-formed.
    //
    // The early-out preserves the pre-coalesce loop's behaviour while
    // still paying only ONE STAC/CLAC pair for the whole pointer
    // walk — vs the pre-coalesce shape's `N` pairs.
    //
    // Pre-allocate the full max_entries slots OUTSIDE the bracket so
    // the per-iteration store under AC=1 cannot trigger the allocator
    // (which is a kernel-only path; running it under AC=1 would defeat
    // the SMAP invariant "AC=1 only while reading user memory").
    let array_src = ptr as *const u64;
    let mut ptrs: alloc::vec::Vec<u64> = alloc::vec::Vec::with_capacity(max_entries);
    ptrs.resize(max_entries, 0);
    let ptrs_dst: *mut u64 = ptrs.as_mut_ptr();
    let mut count = 0usize;
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        while count < max_entries {
            let p = core::ptr::read_volatile(array_src.add(count));
            if p == 0 {
                break;
            }
            *ptrs_dst.add(count) = p;
            count += 1;
        }
    }
    ptrs.truncate(count);
    if count == 0 {
        return result;
    }

    // Per-string range checks — pure arithmetic, no bracket.  A bad
    // pointer truncates the argv at that index, matching the
    // pre-coalesce behaviour where `read_cstring_from_user` would
    // silently return an empty slice on a NULL/invalid pointer.
    let mut valid_count = 0usize;
    while valid_count < count {
        let p = ptrs[valid_count];
        if p == 0 || !crate::syscall::validate_user_ptr(p, 1) {
            break;
        }
        valid_count += 1;
    }
    if valid_count == 0 {
        return result;
    }

    // Phase B — measure every cstring length under ONE SMAP bracket so
    // Phase C can size the staging allocation exactly (avoiding the
    // 128 KiB worst-case-ARG_MAX upfront alloc that would dwarf the
    // typical 1-2 KiB argv/envp).  The length is the unterminated-byte
    // count, capped at `string_scan_max` per the existing per-string
    // bound.
    let mut lens: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(valid_count);
    lens.resize(valid_count, 0);
    let lens_dst: *mut usize = lens.as_mut_ptr();
    let mut total_len: usize = 0;
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        for i in 0..valid_count {
            let src = ptrs[i] as *const u8;
            let mut len = 0usize;
            while len < string_scan_max {
                if *src.add(len) == 0 {
                    break;
                }
                len += 1;
            }
            *lens_dst.add(i) = len;
            total_len = total_len.saturating_add(len);
            if total_len > arg_max_bytes {
                // Per POSIX `execve(2)` `E2BIG`: exceeding the kernel-
                // side argv/envp byte budget is a fatal condition.  We
                // truncate here (matching the pre-coalesce silent-cap
                // behaviour) — surfacing E2BIG would change the
                // observable contract.
                break;
            }
        }
    }
    // Truncate `valid_count` if Phase B's byte-budget cap stopped early
    // (the last `lens[i]` past the cap is still 0 from the resize).
    while valid_count > 0 && total_len > arg_max_bytes {
        valid_count -= 1;
        total_len = total_len.saturating_sub(lens[valid_count]);
    }
    if valid_count == 0 {
        return result;
    }

    // Phase C — allocate exact-sized staging buffer (one allocation,
    // no bracket).  Total size is the sum of all string lengths, which
    // for a typical Mozilla content-process execve is ~1-2 KiB rather
    // than the 128 KiB ARG_MAX worst case.
    let mut staging: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(total_len);
    staging.resize(total_len, 0);
    let staging_ptr: *mut u8 = staging.as_mut_ptr();

    // Compute per-string offsets up front (pure arithmetic).
    let mut offsets: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(valid_count);
    {
        let mut acc = 0usize;
        for i in 0..valid_count {
            offsets.push(acc);
            acc += lens[i];
        }
    }

    // Phase D — copy every cstring body into the staging buffer under
    // ONE SMAP bracket.  Lengths are known precisely from Phase B so
    // each inner memcpy is a tight bounded loop with no per-byte NUL
    // check.
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        for i in 0..valid_count {
            let src = ptrs[i] as *const u8;
            let dst = staging_ptr.add(offsets[i]);
            let len = lens[i];
            // Note: cannot use `core::ptr::copy_nonoverlapping` here
            // because LLVM may lower it to a libc-style memcpy whose
            // body lives outside the bracket span (cf. the SeqCst
            // fence rationale in `smap::UserGuard`).  A byte-by-byte
            // loop with `read_volatile` keeps every read syntactically
            // inside the bracket scope.
            let mut k = 0usize;
            while k < len {
                *dst.add(k) = core::ptr::read_volatile(src.add(k));
                k += 1;
            }
        }
    }

    // Phase E — owned String materialisation (no bracket; runs with
    // AC=0 so the allocator path is SMAP-safe).
    result.reserve_exact(valid_count);
    for i in 0..valid_count {
        let bytes = &staging[offsets[i]..offsets[i] + lens[i]];
        result.push(alloc::string::String::from_utf8_lossy(bytes).into_owned());
    }
    result
}

/// Marshal a Linux `struct sockaddr_in` into a user buffer for
/// `getsockname(2)` / `getpeername(2)`.
///
/// Layout (16 bytes, network byte order for `sin_port`/`sin_addr`):
///   off  0: sin_family   (u16, host order; AF_INET = 2)
///   off  2: sin_port     (u16, BE)
///   off  4: sin_addr     (4 × u8, BE)
///   off  8: sin_zero     (8 × u8, must be zero per IEEE 1003.1)
///
/// Honours the in/out semantics of `addrlen`: writes at most `cap` bytes
/// into the user buffer (truncation is permitted), then unconditionally
/// writes the full struct size (16) back into `*addrlen` so callers can
/// detect truncation.
fn write_sockaddr_in(addr_ptr: u64, addrlen_ptr: *mut u32,
                      ip: [u8; 4], port: u16, cap: usize) {
    let mut buf = [0u8; 16];
    buf[0] = 2;                              // sin_family lo (AF_INET)
    buf[1] = 0;                              // sin_family hi
    let p = port.to_be_bytes();
    buf[2] = p[0]; buf[3] = p[1];            // sin_port
    buf[4] = ip[0]; buf[5] = ip[1];
    buf[6] = ip[2]; buf[7] = ip[3];          // sin_addr
    // sin_zero already zero.
    let n = cap.min(16);
    // SMAP bracket — both writes target user buffers in the syscall path.
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::ptr::copy_nonoverlapping(buf.as_ptr(), addr_ptr as *mut u8, n);
        core::ptr::write(addrlen_ptr, 16u32);
    }
}

/// Test-only re-export of [`write_sockaddr_in`] so the headless suite
/// can exercise the truncation/in-out semantics in isolation without
/// driving the full recvfrom syscall stub from kernel space.
#[doc(hidden)]
pub fn test_write_sockaddr_in(addr_ptr: u64, addrlen_ptr: *mut u32,
                               ip: [u8; 4], port: u16, cap: usize) {
    write_sockaddr_in(addr_ptr, addrlen_ptr, ip, port, cap);
}

/// Dispatch a Linux x86_64 syscall.
///
/// Maps Linux syscall numbers to AstryxOS handlers, handling differences
/// in argument encoding (e.g., C strings vs ptr+len for paths).
pub fn dispatch(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    // ── Vfork sibling-syscall tagger (diagnostic-only) ──────────────────────
    // Fires exactly once per syscall entry.  Off-path cost is a single
    // relaxed atomic load + branch (no VFORK window active → returns
    // immediately).  When a window IS active, any thread that shares the
    // parent's PID but is not the parent itself logs one bounded
    // `[VFORK-SIB]` line.  See `vfork_diag.rs` for the full rationale.
    #[cfg(feature = "vfork-canary-diag")]
    crate::subsys::linux::vfork_diag::maybe_log_sibling_syscall(num);

    // ── D15 `RegisteredThread::mThreadInfo` watcher (diagnostic-only) ──────
    // Off-path cost on every Linux syscall when D15 is built: a single
    // pid+tid compare and one relaxed atomic load.  Once the arm has
    // been claimed (within the first ~few syscalls of firefox-bin
    // pid=1) the fast-path guard bails immediately.  See
    // `d15_mthread_watch.rs` for the full strategy + signature classes.
    #[cfg(feature = "d15-mthread-watch")]
    crate::subsys::linux::d15_mthread_watch::try_arm_at_syscall(
        crate::proc::current_pid_lockless(),
        crate::proc::current_tid(),
    );

    // ── D16 SSP-canary saved-slot watcher (diagnostic-only) ────────────────
    // Late-arm of the user-VA DR channel.  Same fast-path cost as D15:
    // one pid+tid compare and one relaxed atomic load on each Linux
    // syscall when D16 is built; bails immediately once the arm has
    // been claimed.  The complementary PHYS_OFF channel is armed eagerly
    // at execve completion against the deterministic backing phys
    // `0x127114c0`.  See `d16_canary_watch.rs` for the full strategy.
    #[cfg(feature = "d16-canary-watch")]
    crate::subsys::linux::d16_canary_watch::try_arm_at_syscall(
        crate::proc::current_pid_lockless(),
        crate::proc::current_tid(),
    );

    // ── Record/replay: virtual tick advance + structured per-syscall record ──
    // Off-path cost when `--features record-replay` is OFF is zero (the
    // entire block is `cfg`-elided).  When ON, we advance the kernel's
    // frozen virtual tick counter (one relaxed atomic increment) and
    // emit one self-describing `[SC-REC] {...}` JSON-shaped serial line
    // carrying pid, tid, sc#, all six args, user RIP at entry, live
    // IA32_FS_BASE, the per-process vfork-generation id, and the
    // strictly increasing `ord` sequence ordinal.  Same workload + same
    // seed → byte-identical `[SC-REC]` streams across runs (validation
    // target: first ~500 records; see
    // `docs/RECORD_REPLAY_2026-05-23.md`).  Refs: Intel SDM Vol. 3A
    // §3.4.4.1 (IA32_FS_BASE); POSIX `clock_gettime(3)`.
    #[cfg(feature = "record-replay")]
    {
        crate::record_replay::advance_virtual_ticks();
        let user_rip = unsafe { crate::syscall::get_user_rip() };
        let fs_base = unsafe { crate::hal::rdmsr(0xC000_0100) };
        let pid_now = crate::proc::current_pid_lockless();
        let tid_now = crate::proc::current_tid();
        // Best-effort: read the per-process VmSpace generation if we can
        // get a non-blocking handle on the process table.  Skip silently
        // (gen=0) on contention — the ordinal already gives total order.
        let gen_id = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter()
                .find(|p| p.pid == pid_now)
                .and_then(|p| p.vm_space.as_ref())
                .map(|s| s.generation.load(core::sync::atomic::Ordering::Relaxed))
                .unwrap_or(0)
        };
        crate::record_replay::record_syscall_entry(
            num, arg1, arg2, arg3, arg4, arg5, arg6,
            pid_now, tid_now, user_rip, fs_base, gen_id,
        );
    }

    // ── Tier-0 trace: one self-contained line per syscall entry ──────────────
    // Grepped by qemu-harness.py via `^\[SC\] `.  User RIP comes from the
    // per-CPU syscall_entry stash (set by the naked-asm stub before dispatch).
    // `caller_rip` is `[user_rsp]` at entry — the address that called the libc
    // syscall wrapper, which resolves to a Mozilla / firefox-bin function.
    //
    // a4/a5/a6 are also printed so e.g. epoll_wait's timeout (a4),
    // futex's timeout pointer (a4) and op-flags decoded later, and
    // clock_gettime's clock-id (a1, already covered) are all visible
    // without re-entering the kernel.  Phase 3A.
    #[cfg(feature = "syscall-trace")]
    {
        let user_rip = unsafe { crate::syscall::get_user_rip() };
        let caller_rip = crate::syscall::get_user_caller_rip();
        // Stack-depth-from-base augments the standard [SC] line for the
        // STACK_CANARY_CORRUPT (post-task #229) investigation.  `ksp` is
        // the live kernel RSP at dispatch time; `kdepth` is
        // `(kstack_top - ksp)`.  Both default to 0 when the thread's
        // kstack span is not recorded (e.g. idle paths).
        let tid_now = crate::proc::current_tid();
        let pid_now = crate::proc::current_pid_lockless();
        let rsp_live = crate::proc::current_kernel_rsp_live();
        let (kstack_base, kstack_size) = {
            let threads = crate::proc::THREAD_TABLE.lock();
            threads.iter().find(|t| t.tid == tid_now)
                .map(|t| (t.kernel_stack_base, t.kernel_stack_size))
                .unwrap_or((0, 0))
        };
        let kdepth = if kstack_base > 0 {
            kstack_base.wrapping_add(kstack_size).wrapping_sub(rsp_live)
        } else { 0 };
        // Firehose: one ~150-byte line per syscall.  Route through the
        // near-zero-overhead guest-RAM log ring (drivers::log_ring) instead of
        // the per-byte COM1 16550 PIO path — under KVM the latter is ~one
        // VM-exit per byte (Intel SDM Vol. 3C §25.1.3), which dominates a
        // high-syscall-rate boot.  `serial_fast_println!` falls back to COM1
        // when the ring sink is disabled, so the trace is never lost.
        crate::serial_fast_println!(
            "[SC] pid={} tid={} nr={} rip={:#x} cr={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x} a6={:#x} ksp={:#x} kdepth={:#x}",
            pid_now,
            tid_now,
            num,
            user_rip,
            caller_rip,
            arg1, arg2, arg3, arg4, arg5, arg6,
            rsp_live, kdepth,
        );
    }

    // ── Phase 3B: periodic user-stack snapshot on hot syscalls ──────────────
    // Triggered every Nth `clock_gettime` / `gettimeofday` / `futex` call from
    // any user pid (>= 12 to skip kernel init / shell processes).  Emits an
    // `[SC-USTACK]` line with the saved RBP chain (up to 16 frames) so the
    // host post-processor can resolve every frame to a `libxul.so + offset`
    // symbol via the `[FFTEST/mmap-so]` load-base table.  All reads go through
    // `virt_to_phys_in` so a corrupt or unmapped RBP cannot fault the syscall
    // handler.
    //
    // The snapshot is keyed on `(pid, tid, num)` so every distinct caller
    // gets its own emission cadence — important because Firefox runs many
    // worker threads alongside the busy-polling main thread.  We bound the
    // total emissions per (pid,tid,num) tuple at 8 to keep log size sane.
    //
    // Sleeping syscalls included (35=nanosleep, 230=clock_nanosleep,
    // 202=futex, 232=epoll_wait, 271=ppoll, 270=pselect6, 449=futex_waitv)
    // so we can confirm the Phase 3C "zero sleeping syscalls" observation
    // empirically rather than from the histogram alone.
    //
    // Each snapshot is a ~256–512 byte serial line (the leaf RIP, the
    // RBP-walked frames, and up to 16 stack-scan candidates).  Under the
    // chunked 16550 driver that costs ~16–32 cli windows per snapshot, so
    // we gate this behind `firefox-trace-verbose` and keep the demo-path
    // build clean.  The default `firefox-test` still emits the `[SC]` line
    // (under `syscall-trace`), which carries the leaf RIP and caller RIP —
    // sufficient for throughput measurement.
    #[cfg(all(feature = "firefox-test-core", feature = "firefox-trace-verbose"))]
    {
        // First PID at which the user-stack snapshot emitter starts firing.
        // Lower PIDs belong to the kernel bringup chain (idle, init, X11
        // server, the test runner's own helpers) — none of them produce
        // useful Firefox-side stack traces, and emitting for them just
        // pollutes the serial log during boot.  PID 12 is the first
        // PID assigned to a Firefox-equivalent user process under the
        // current bringup ordering; bump this if the boot chain grows.
        const FIRST_USERLAND_PID: u64 = 12;

        let pid_now = crate::proc::current_pid_lockless();
        let tid_now = crate::proc::current_tid();
        let is_hot = matches!(num,
            96 | 228 |        // gettimeofday, clock_gettime
            35 | 230 |        // nanosleep, clock_nanosleep
            202 | 449 |       // futex, futex_waitv
            232 | 270 | 271   // epoll_wait, pselect6, ppoll
        );
        if pid_now >= FIRST_USERLAND_PID && is_hot {
            // 64-slot ring of per-(pid,tid,num) emission counters.  The slot
            // index is a small hash of tid and syscall number, so distinct
            // (tid,num) tuples that hash to the same slot SHARE the 8-emission
            // budget — a deliberate trade of perfect per-tuple isolation for
            // a fixed-size statics table.  In practice Firefox runs ~30-50
            // worker threads against ~10 hot syscalls, so collisions cost
            // a small number of missed snapshots, never a runaway log.
            static USTACK_N: [core::sync::atomic::AtomicU64; 64] = {
                const Z: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0);
                [Z; 64]
            };
            let slot = ((tid_now as usize).wrapping_mul(31)
                ^ (num as usize).wrapping_mul(7)) & 63;
            let n = USTACK_N[slot].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            // Every 500th hit per slot, capped at 8 emissions — gives several
            // samples per active worker thread without flooding the serial log.
            if n % 500 == 0 && n / 500 < 8 {
                emit_user_stack_snapshot(num, n / 500);
            }
        }
    }

    // ── Per-PID debug trace ───────────────────────────────────────────────────
    let trace_pid = crate::syscall::DEBUG_TRACE_PID.load(core::sync::atomic::Ordering::Relaxed);
    let do_trace = trace_pid != 0 && crate::proc::current_pid_lockless() == trace_pid;
    if do_trace {
        crate::serial_println!("[TRACE] pid={} sys={} a1={:#x} a2={:#x} a3={:#x}",
            trace_pid, num, arg1, arg2, arg3);
    }

    // ── Global syscall counter (used by Firefox oracle test) ─────────────────
    {
        let pid = crate::proc::current_pid_lockless();
        if pid >= 1 {
            crate::syscall::FIREFOX_SYSCALL_COUNT
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }

    // ── Per-process activity metrics: enter ──────────────────────────────────
    // Single bounds-check + one Acquire load + one Relaxed counter bump in
    // the live-PID path.  See `crate::proc::proc_metrics::enter_syscall`.
    // The tick read is wait-free (Relaxed atomic load).
    let _metrics_pid = crate::proc::current_pid_lockless();
    if _metrics_pid >= 1 {
        let tick = crate::arch::x86_64::irq::get_ticks();
        crate::proc::proc_metrics::enter_syscall(_metrics_pid, num, tick);
    }

    // ── Per-process syscall ring buffer (firefox-test only) ──────────────────
    // Record the call at entry so that the path/return-value hooks inside
    // sys_read_linux / sys_open_linux can attach extra context before we
    // patch the return value after the match dispatch completes.
    #[cfg(feature = "firefox-test-core")]
    let ring_entry_idx = {
        let pid = crate::proc::current_pid_lockless();
        // Auto-track every user-process PID >= 1 that makes a Linux syscall —
        // this includes Firefox (pid 28 in the current harness run) plus any
        // children it spawns.  Enabling is idempotent.
        if pid >= 1 {
            crate::syscall::ring::enable_for(pid);
            let rip = unsafe { crate::syscall::get_user_rip() };
            // Also grab `[user_rsp]` — the caller's return address — so the
            // post-processor can resolve to a libxul/firefox-bin symbol
            // directly, not just to the libc `syscall()` wrapper.
            let caller_rip = crate::syscall::get_user_caller_rip();
            crate::syscall::ring::begin(
                pid, num, arg1, arg2, arg3, arg4, arg5, arg6, rip, caller_rip,
            )
        } else {
            None
        }
    };
    #[cfg(not(feature = "firefox-test-core"))]
    let _ring_entry_idx: Option<usize> = None;

    // ── Transient debug trace: log Linux syscalls from user processes ─────────
    //
    // Each `[LINUX-SYS]` line is ~70–90 bytes; emitting one per syscall under
    // `firefox-test,syscall-trace` more than doubles the per-syscall serial
    // output and, under KVM, pins CPU 2 in the 16550 driver before Firefox
    // can reach steady state.  Demote to the opt-in `firefox-trace-verbose`
    // feature — the `[SC]` / `[SC-RET]` pair (under `syscall-trace`) already
    // identifies every syscall by number, pid, tid, and full argv.  Keep the
    // non-`firefox-test` branch (which limits to 500 lines from pid >= 12)
    // since it is bounded and useful for early-boot diagnostics.
    #[cfg(all(feature = "firefox-test-core", feature = "firefox-trace-verbose"))]
    {
        static TRACE_N: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let pid = crate::proc::current_pid_lockless();
        if pid >= 1 {
            let n = TRACE_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 10000 {
                crate::serial_println!("[LINUX-SYS] #{} pid={} num={} a1={:#x}", n, pid, num, arg1);
            }
        }
    }
    #[cfg(not(feature = "firefox-test-core"))]
    {
        static TRACE_N: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let pid = crate::proc::current_pid_lockless();
        if pid >= 12 {
            let n = TRACE_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 500 {
                crate::serial_println!("[LINUX-SYS] #{} pid={} num={} a1={:#x} a2={:#x}", n, pid, num, arg1, arg2);
            }
        }
    }
    // ── Lazy SIGALRM delivery — check alarm deadline before every syscall ────
    // The timer ISR cannot safely acquire PROCESS_TABLE, so alarm expiry is
    // detected here instead.  This guarantees delivery within one syscall of
    // expiry, which meets POSIX requirements for non-real-time scheduling.
    {
        let pid = crate::proc::current_pid_lockless();
        if pid >= 1 {
            check_and_deliver_alarm(pid);
        }
    }

    // Stash the ring-entry index in a per-CPU slot so sys_read_linux /
    // sys_open_linux can attach path / read-content context to the pending
    // entry without needing to thread it through every syscall signature.
    // Syscalls are serialised per CPU, so a single atomic per CPU is safe.
    #[cfg(feature = "firefox-test-core")]
    crate::subsys::linux::syscall_ring::set_current_entry(ring_entry_idx);

    // Route through dispatch_body() so an early `return` inside any match
    // arm still falls through to the exit hooks below (ring::end(),
    // [SC-RET] trace) rather than bypassing them.
    let ret: i64 = dispatch_body(num, arg1, arg2, arg3, arg4, arg5, arg6);

    // ── Close out the ring entry with the syscall's return value ─────────────
    #[cfg(feature = "firefox-test-core")]
    {
        let pid = crate::proc::current_pid_lockless();
        crate::syscall::ring::end(pid, ring_entry_idx, ret);
        crate::subsys::linux::syscall_ring::clear_current_entry();
    }

    // ── Per-process activity metrics: leave ──────────────────────────────────
    // Clears `last_sc_nr` to -1 so the periodic dump's stuck detector does
    // not flag a syscall that legitimately returned to user-mode.
    if _metrics_pid >= 1 {
        crate::proc::proc_metrics::leave_syscall(_metrics_pid);
    }

    // ── Record/replay: advance virtual ticks on syscall exit ───────────
    // Paired with the entry-side bump so every syscall contributes
    // exactly two virtual ticks.  See `crate::record_replay`.
    #[cfg(feature = "record-replay")]
    crate::record_replay::advance_virtual_ticks();

    // ── Tier-0 trace: paired return value line ────────────────────────────
    // Hex formatting keeps negative errno values grep-friendly
    // (e.g. -2 → 0xfffffffffffffffe, -13 → 0xfffffffffffffff3).
    // Emitted AFTER the handler returns but BEFORE the caller writes RAX
    // back to the user frame, so the trace reflects the actual syscall
    // result the process will observe.
    // Firehose return-side line — same per-syscall cadence as `[SC]`; route
    // through the cheap guest-RAM ring (see the `[SC]` emit site above).
    #[cfg(feature = "syscall-trace")]
    crate::serial_fast_println!(
        "[SC-RET] pid={} tid={} nr={} ret={:#x}",
        crate::proc::current_pid_lockless(),
        crate::proc::current_tid(),
        num,
        ret as u64,
    );

    // ── Dead-thread drain (exit_group SMP coherence) ──────────────────────
    //
    // A concurrent exit_group(2) from another thread in this process may
    // have marked the current thread Dead while it was mid-syscall on a
    // separate CPU.  Per POSIX exit_group(2), all threads in the process
    // must terminate; returning to userspace with freed page tables would
    // be a use-after-free (Intel SDM Vol. 3A §4.10 — CR3 loaded after PML4
    // is freed causes unpredictable TLB behaviour).
    //
    // Check here, after all syscall-exit hooks have run and before the asm
    // stub executes SYSRETQ.  If Dead, call exit_thread() which switches to
    // the kernel CR3, marks this thread Zombie, and calls schedule() — so
    // control never returns to userspace.  The check is a single lock +
    // state comparison; on the common path (not Dead) it adds one
    // THREAD_TABLE lock round-trip, which is negligible vs. the syscall cost.
    //
    // EXCLUDED: sys_exit (60) and sys_exit_group (231).  Those syscalls call
    // free_process_memory() and exit_thread() directly as part of their own
    // execution path (POSIX exit(2) / exit_group(2)).  Reaching this drain
    // after either of them returns would invoke exit_thread() a second time,
    // double-decrementing thread-resource refcounts on the kstack and signal
    // stack before vm_space.take() can short-circuit — producing the
    // REFCOUNT/DEC-UNDERFLOW seen on the Firefox demo path.  The drain is
    // for SMP sibling cleanup only; the exit syscalls handle their own thread
    // on the caller's path.
    if num != 60 && num != 231 {
        let tid = crate::proc::current_tid();
        let is_dead = {
            let threads = crate::proc::THREAD_TABLE.lock();
            threads.iter()
                .find(|t| t.tid == tid)
                .map(|t| t.state == crate::proc::ThreadState::Dead)
                .unwrap_or(false)
        };
        if is_dead {
            // Switch to kernel CR3 before any teardown.
            let kc3 = crate::mm::vmm::get_kernel_cr3();
            if kc3 != 0 {
                let cur = crate::mm::vmm::get_cr3();
                if cur != kc3 {
                    crate::mm::tlb::note_cr3_load(kc3);
                    unsafe { crate::mm::vmm::switch_cr3(kc3); }
                    crate::mm::tlb::note_cr3_unload(cur);
                }
            }
            crate::proc::exit_thread(0);
            // exit_thread() calls schedule() which never returns to this thread.
            unreachable!();
        }
    }

    ret
}

/// Inner body of Linux syscall dispatch.  Isolated from the public
/// `dispatch()` wrapper so an early `return` inside any match arm still
/// falls through to the exit hooks (ring::end(), [SC-RET]) rather than
/// bypassing them.
fn dispatch_body(num: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> i64 {
    // Linux UAPI clone(2)/clone3(2) flag bits.  Hoisted to function scope so
    // the clone / clone3 / fork-style branches share a single source of truth
    // instead of redeclaring them in every match arm.  Values per
    // `include/uapi/linux/sched.h`.
    const CLONE_SIGHAND:       u64 = 0x00000800;
    const CLONE_VFORK:         u64 = 0x00004000;
    const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;

    match num {
        // 0: read(fd, buf, count)
        0 => sys_read_linux(arg1, arg2, arg3),
        // 1: write(fd, buf, count)
        1 => sys_write_linux(arg1, arg2, arg3),
        // 2: open(pathname, flags, mode) — user-mode entry gate on pathname.
        // CWE-823.  In-kernel test callers wrap their `dispatch_linux` call
        // in `KernelDispatchGuard` (see `dispatch_linux_kernel`) which sets
        // a per-CPU bypass flag; real user-mode SYSCALL traffic never sets
        // that flag and is gated as designed.
        2 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && !user_path_ptr_ok(arg1) { return -14; }
            sys_open_linux(arg1, arg2, arg3)
        }
        // 3: close(fd)
        3 => {
            let fd = arg1 as usize;
            let pid = crate::proc::current_pid_lockless();
            // If it's a unix socket fd, close the underlying unix socket.
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                crate::net::unix::close(unix_id);
            // If it's an AF_INET socket fd, close the underlying socket.
            } else if crate::syscall::is_socket_fd(pid, fd) {
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                crate::net::socket::socket_close(socket_id);
            }
            // If it's an eventfd, drop one open-file-description reference.
            // The counter slot is freed only when the LAST reference goes
            // away (POSIX close(2)) — an eventfd inherited across fork(2)
            // or duplicated via dup(2)/SCM_RIGHTS is one shared object, so
            // a child's pre-execve close-on-exec scrub must not destroy
            // the counter the parent still writes to.
            if crate::syscall::is_eventfd_fd(pid, fd) {
                let efd_id = crate::syscall::get_eventfd_id(pid, fd);
                crate::ipc::eventfd::close(efd_id);
            }
            // Free timerfd / signalfd / inotifyfd slots.
            if crate::syscall::is_timerfd_fd(pid, fd) {
                crate::ipc::timerfd::close(crate::syscall::get_timerfd_id(pid, fd));
            }
            if crate::syscall::is_signalfd_fd(pid, fd) {
                crate::ipc::signalfd::close(crate::syscall::get_signalfd_id(pid, fd));
            }
            if crate::syscall::is_inotify_fd(pid, fd) {
                crate::ipc::inotify::close(crate::syscall::get_inotify_id(pid, fd));
            }
            // If it's an epoll fd, remove the EpollInstance — but ONLY
            // when this close is dropping the LAST FileDescriptor that
            // references the underlying epoll object.  Symmetric with
            // the by-id lookup in sys_epoll_ctl/wait: epoll instances
            // are now keyed by `inode` (the epoll id stamped at
            // create time), and dup(2)/fcntl(F_DUPFD) clones the
            // FileDescriptor including its inode — so multiple fds
            // can point at the same instance.  Retiring the instance
            // on first close would orphan watches the dup'd fds still
            // care about.
            //
            // POSIX dup(2): "after a successful return from one of
            // these functions, the old and new file descriptors may be
            // used interchangeably. ... When one of the descriptors is
            // closed, the file is not closed if the other descriptor
            // is still open."  Epoll-on-Linux extends this to the
            // watch list (epoll(7): the interest list is associated
            // with the open file description, not the fd).
            {
                let close_epoll_id: Option<u64> = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().find(|p| p.pid == pid)
                        .and_then(|p| p.file_descriptors.get(fd))
                        .and_then(|f| f.as_ref())
                        .and_then(|f| if f.open_path == "[epoll]" {
                            Some(f.inode)
                        } else {
                            None
                        })
                };
                if let Some(eid) = close_epoll_id {
                    let mut procs = crate::proc::PROCESS_TABLE.lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                        // Count surviving FileDescriptors that point at
                        // this epoll id, EXCLUDING the one we're about
                        // to close (fd == this slot).
                        let other_refs = p.file_descriptors.iter().enumerate()
                            .filter(|(i, _)| *i != fd)
                            .filter_map(|(_, f)| f.as_ref())
                            .filter(|f| f.open_path == "[epoll]" && f.inode == eid)
                            .count();
                        if other_refs == 0 {
                            p.epoll_sets.retain(|e| e.id != eid);
                        }
                    }
                }
            }
            match crate::vfs::close(pid, fd) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 4: stat(pathname, statbuf) — user-mode entry gate (CWE-823).
        4 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && !user_path_ptr_ok(arg1) { return -14; }
            sys_stat_linux(arg1, arg2)
        }
        // 5: fstat(fd, statbuf)
        5 => sys_fstat_linux(arg1 as usize, arg2 as *mut u8),
        // 6: lstat(pathname, statbuf) — same as stat for us (no symlink follow).
        // User-mode entry gate (CWE-823).
        6 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && !user_path_ptr_ok(arg1) { return -14; }
            sys_stat_linux(arg1, arg2)
        }
        // 8: lseek(fd, offset, whence)
        8 => crate::syscall::sys_lseek(arg1 as usize, arg2 as i64, arg3 as u32),
        // 9: mmap(addr, len, prot, flags, fd, offset)
        9 => crate::syscall::sys_mmap(arg1, arg2, arg3 as u32, arg4 as u32, arg5, arg6),
        // 10: mprotect(addr, len, prot)
        10 => sys_mprotect(arg1, arg2, arg3),
        // 11: munmap(addr, len)
        11 => crate::syscall::sys_munmap(arg1, arg2),
        // 12: brk(new_brk)
        12 => crate::syscall::sys_brk(arg1),
        // 13: rt_sigaction(sig, act, oldact, sigsetsize)
        13 => sys_rt_sigaction_linux(arg1, arg2, arg3, arg4),
        // 14: rt_sigprocmask(how, set, oldset, sigsetsize)
        14 => sys_rt_sigprocmask_linux(arg1, arg2, arg3, arg4),
        // 15: rt_sigreturn
        15 => crate::syscall::sys_sigreturn(),
        // 16: ioctl(fd, request, arg)
        16 => {
            let fd_num = arg1 as usize;
            let request = arg2;
            let arg_ptr = arg3 as *mut u8;
            crate::syscall::sys_ioctl(fd_num, request, arg_ptr)
        }
        // 20: writev(fd, iov, iovcnt)
        20 => sys_writev(arg1, arg2, arg3),
        // 21: access(pathname, mode) — user-mode entry gate (CWE-823).
        21 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && !user_path_ptr_ok(arg1) { return -14; }
            sys_access(arg1, arg2)
        }
        // 24: sched_yield
        24 => {
            crate::sched::yield_cpu();
            0
        }
        // 39: getpid
        39 => crate::proc::current_pid_lockless() as i64,
        // 7: poll(fds, nfds, timeout) — wait for events on fds
        7 => {
            let nfds = arg2 as i64;
            let pid  = crate::proc::current_pid_lockless();
            let timeout_ms = arg3 as i64; // -1 = block; 0 = no wait

            if nfds <= 0 || arg1 == 0 {
                return 0;
            }

            // Poll entry logging disabled — deep call stack + serial formatting
            // was contributing to kernel stack overflow for Firefox.
            #[cfg(feature = "firefox-test-core")]
            if false && pid >= 1 {
                crate::serial_println!("[POLL_ENTRY] pid={} nfds={} timeout={}",
                    pid, nfds, timeout_ms);
            }

            // Inner check: evaluate all pollfds, write revents, return ready count.
            // struct pollfd { int fd; short events; short revents; } = 8 bytes
            //
            // SMAP discipline: bracket each pollfd access individually
            // because crate::syscall::poll_revents is a kernel-only path
            // (waitlist + fd table) — holding AC=1 across it would defeat
            // SMAP's purpose of confining user-page access.
            let do_check = |clear: bool, log: bool| -> i64 {
                let mut ready = 0i64;
                for i in 0..nfds as u64 {
                    let base = (arg1 + i * 8) as *mut u8;
                    let (fd_val, events) = unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        (core::ptr::read_unaligned(base as *const i32),
                         core::ptr::read_unaligned(base.add(4) as *const u16))
                    };
                    if fd_val < 0 {
                        if clear {
                            unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                core::ptr::write_unaligned(base.add(6) as *mut u16, 0);
                            }
                        }
                        continue;
                    }
                    let revents = crate::syscall::poll_revents(pid, fd_val as usize, events);
                    // Per-fd poll logging disabled to reduce kernel stack pressure.
                    let _ = log;
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::write_unaligned(base.add(6) as *mut u16, revents);
                    }
                    if revents != 0 { ready += 1; }
                }
                ready
            };

            let ready = do_check(false, true);
            if ready == 0 && timeout_ms != 0 {
                // Pump X11 once immediately after the initial check so the server can
                // process any pending requests from Firefox and write replies to its
                // socket buffer.  Then check AGAIN before the first yield — if X11
                // already wrote a reply, we can return without yielding at all.
                crate::x11::poll();
                // Pump the network stack so any e1000 RX descriptors filled
                // by the NIC since the last tick get drained into per-socket
                // queues before we re-evaluate readiness.  Without this, a
                // userspace DNS resolver that polls within a 5 ms window of
                // its `write()` sees the binding queue empty even though the
                // reply was DMA'd into the RX ring (RFC 1035 §4.2.1 retry
                // budget is too tight for the 1 s resync floor to cover).
                crate::net::poll();
                let r = do_check(true, true);
                if r > 0 {
                    #[cfg(feature = "firefox-test-trace")]
                    if pid >= 1 { crate::serial_fast_println!("[POLL_RET] pid={} ret={} (post-x11-poll)", pid, r); }
                    return r;
                }
                // Block the thread until an fd becomes ready or timeout expires.
                // For timeout_ms == -1 (infinite), block indefinitely.
                // For timeout_ms > 0, block for at most that many ms.
                // Each iteration sleeps 1 tick (10ms), pumps X11, and re-checks.
                let deadline_tick = if timeout_ms < 0 {
                    u64::MAX // infinite
                } else {
                    let now = crate::arch::x86_64::irq::get_ticks();
                    now + ((timeout_ms as u64) / 10).max(1)
                };
                // Per-object interest set: read the watched fds out of the user
                // pollfd array (under SMAP) once, then map each to its concrete
                // readiness object so the per-object poll-bell drain wakes this
                // poller only on edges of the EXACT pipes/sockets/eventfds it
                // watches (intra-class herd collapse).  A negative pollfd
                // (`fd < 0`, ignored per poll(2)) contributes nothing.
                // Conservative superset: an unclassifiable fd ⇒ wake-on-class.
                let (bell_mask, bell_objects) = {
                    let mut fds: alloc::vec::Vec<usize> =
                        alloc::vec::Vec::with_capacity(nfds as usize);
                    for i in 0..nfds as u64 {
                        let base = (arg1 + i * 8) as *const u8;
                        let fd_val = unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            core::ptr::read_unaligned(base as *const i32)
                        };
                        if fd_val >= 0 {
                            fds.push(fd_val as usize);
                        }
                    }
                    bell_watch_for_fds(pid, fds.into_iter())
                };
                loop {
                    // Park on the global IPC poll bell rather than spin-
                    // sleeping at 100 Hz.  Any pipe write / eventfd post /
                    // unix-socket message rings the bell (see
                    // `crate::ipc::waitlist::ring_poll_bell`), waking us
                    // promptly to re-evaluate the fd set.  The scheduler
                    // tick wakes us anyway when `wake_tick == deadline`,
                    // so a missed bell is bounded by the timeout (with
                    // `u64::MAX` for infinite waits, the bell is the only
                    // wake mechanism — its single firing point is every
                    // pipe/eventfd write).
                    //
                    // The readiness closure passed here is re-run by
                    // `wait_poll_event` *under the POLL_BELL lock* before it
                    // commits to parking, closing the check-and-park
                    // lost-wakeup window: a writer that rings the bell
                    // between our last `do_check` and the park is serialized
                    // on POLL_BELL, so it either makes us observe ready in
                    // the recheck (we skip parking) or finds us already
                    // enqueued (it drains us).  `do_check(false, false)` is a
                    // side-effect-light readiness probe (it only writes the
                    // idempotent revents bits, recomputed after the wake).
                    let ready_in_window =
                        crate::ipc::waitlist::wait_poll_event_obj(
                            deadline_tick, bell_mask, &bell_objects,
                            || do_check(false, false) > 0);
                    if !ready_in_window {
                        // We actually parked and woke — pump X11 so replies
                        // appear in socket buffers, and pump the NIC RX ring +
                        // UDP/TCP demux so wire-side events become poll-
                        // visible.  See the matching pre-wait pump above.
                        crate::x11::poll();
                        crate::net::poll();
                    }
                    let r = do_check(true, true);
                    if r > 0 {
                        #[cfg(feature = "firefox-test-trace")]
                        if pid >= 1 { crate::serial_fast_println!("[POLL_RET] pid={} ret={} (woke)", pid, r); }
                        return r;
                    }
                    if signal_pending(pid) { return -4; } // EINTR
                    let now = crate::arch::x86_64::irq::get_ticks();
                    if now >= deadline_tick { break; }
                }
                #[cfg(feature = "firefox-test-trace")]
                if pid >= 1 { crate::serial_fast_println!("[POLL_RET] pid={} ret=0 (timeout)", pid); }
                0
            } else {
                #[cfg(feature = "firefox-test-trace")]
                if pid >= 1 { crate::serial_fast_println!("[POLL_RET] pid={} ret={} (immediate)", pid, ready); }
                ready
            }
        }
        // 17: pread64(fd, buf, count, offset)
        17 => {
            let fd = arg1 as usize;
            let buf = arg2 as *mut u8;
            let count = arg3 as usize;
            let offset = arg4 as i64;
            let pid = crate::proc::current_pid_lockless();
            // Save, seek, read, restore
            let saved = crate::syscall::sys_lseek(fd, 0, 1 /*SEEK_CUR*/);
            let sk = crate::syscall::sys_lseek(fd, offset, 0 /*SEEK_SET*/);
            if sk < 0 { return sk; }
            let n = crate::vfs::fd_read(pid, fd, buf, count);
            if saved >= 0 { let _ = crate::syscall::sys_lseek(fd, saved, 0); }
            match n {
                Ok(n) => n as i64,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 18: pwrite64(fd, buf, count, offset)
        18 => {
            let fd = arg1 as usize;
            let buf = arg2 as *const u8;
            let count = arg3 as usize;
            let offset = arg4 as i64;
            let pid = crate::proc::current_pid_lockless();
            let saved = crate::syscall::sys_lseek(fd, 0, 1);
            let sk = crate::syscall::sys_lseek(fd, offset, 0);
            if sk < 0 { return sk; }
            let n = crate::vfs::fd_write(pid, fd, buf, count);
            if saved >= 0 { let _ = crate::syscall::sys_lseek(fd, saved, 0); }
            match n {
                Ok(n) => n as i64,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 19: readv(fd, iov, iovcnt) — scatter-gather read
        19 => sys_readv(arg1, arg2, arg3),
        // 29: shmget(key, size, shmflg) — get/create shared memory segment
        29 => crate::ipc::sysv_shm::shmget(arg1 as i32, arg2, arg3 as i32),
        // 30: shmat(shmid, shmaddr, shmflg) — attach shared memory
        30 => crate::ipc::sysv_shm::shmat(arg1 as u32, arg2, arg3 as i32),
        // 31: shmctl(shmid, cmd, buf) — control shared memory (UAPI 31; previously mis-assigned to shmdt)
        31 => crate::ipc::sysv_shm::shmctl(arg1 as u32, arg2 as i32, arg3),
        // 65: semop(semid, sops, nsops) — UAPI 65; previously mis-assigned to shmctl
        // Not yet implemented; return ENOSYS so callers get a clear failure.
        65 => {
            crate::serial_println!("[SYSCALL] semop (65) not implemented — ENOSYS");
            -38 // ENOSYS
        }
        // 67: shmdt(shmaddr) — detach shared memory (UAPI 67; previously dispatched at wrong arm 31)
        67 => crate::ipc::sysv_shm::shmdt(arg1),
        // 32: dup(oldfd) — duplicate fd to lowest available slot
        32 => crate::syscall::sys_dup(arg1 as usize),
        // 33: dup2(oldfd, newfd) — duplicate fd to specific slot
        33 => {
            let ret = crate::syscall::sys_dup2(arg1 as usize, arg2 as usize);
            #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
            {
                let pid = crate::proc::current_pid_lockless();
                if pid == 1 || crate::syscall::ring::is_tracked(pid) {
                    crate::serial_println!("[FF/dup2] pid={} old={} new={} ret={}", pid, arg1, arg2, ret);
                }
            }
            ret
        }
        // 34: pause() — sleep until signal (stub: yield)
        34 => {
            crate::sched::yield_cpu();
            -4 // EINTR
        }
        // 35: nanosleep(req, rem) — struct timespec { tv_sec: i64, tv_nsec: i64 }
        35 => sys_nanosleep_linux(arg1, arg2),
        // 40: sendfile(out_fd, in_fd, offset_ptr, count)
        40 => sys_sendfile(arg1 as usize, arg2 as usize, arg3, arg4 as usize),
        // ── Phase 4: Socket syscalls (sockets as file descriptors) ───────────
        // 41: socket(domain, type, protocol) → fd
        41 => {
            let domain = arg1 as u32;  // AF_INET=2, AF_UNIX=1, AF_INET6=10
            let sock_type = arg2 & 0xFF; // strip SOCK_NONBLOCK/SOCK_CLOEXEC
            // Per `man 2 socket`: SOCK_CLOEXEC = 0o2000000 = 0x80000,
            // SOCK_NONBLOCK = 0o4000 = 0x800.  Both are ORed into the
            // type argument and must be honoured on the resulting fd.
            let cloexec  = (arg2 & 0x80000) != 0;
            let nonblock = (arg2 & 0x00800) != 0;
            let pid = crate::proc::current_pid_lockless();
            if domain == 1 {
                // AF_UNIX: use net::unix module.
                // SOCK_STREAM=1, SOCK_DGRAM=2, SOCK_SEQPACKET=5.
                let kind = match sock_type {
                    1 => crate::net::unix::SockKind::Stream,
                    5 => crate::net::unix::SockKind::SeqPacket,
                    // SOCK_DGRAM and other AF_UNIX types are not yet
                    // supported — return -EPROTONOSUPPORT per POSIX.
                    _ => return -93,
                };
                // Capture caller's effective credentials so a later
                // getsockopt(SO_PEERCRED) on this socket's peer can report
                // them per unix(7) SO_PEERCRED — finding H7 of the
                // 2026-05-16 security audit (CWE-287).
                let (cpid, cuid, cgid) = crate::proc::current_creds_lockless();
                let creds = crate::net::unix::PeerCreds { pid: cpid, uid: cuid, gid: cgid };
                let unix_id = crate::net::unix::create(kind, creds);
                if unix_id == u64::MAX { return -24; } // EMFILE
                crate::syscall::alloc_unix_socket_fd(pid, unix_id, cloexec, nonblock)
            } else if domain == 2 || domain == 10 {
                // AF_INET / AF_INET6
                //
                // Runtime address-family gate (see net::ipver).  A disabled
                // family makes socket(2) fail with EAFNOSUPPORT, matching the
                // documented Linux behaviour when the family is unavailable
                // (e.g. a kernel booted with `ipv6.disable=1`): socket(2) —
                // "EAFNOSUPPORT — the implementation does not support the
                // specified address family".  This is the primary, cleanest
                // enforcement: a userspace resolver's AI_ADDRCONFIG probe sees
                // the family fail and skips it (forcing the working family)
                // rather than building a socket it can never use.
                if domain == 10 && !crate::net::ipver::ipv6_enabled() {
                    return -97; // EAFNOSUPPORT
                }
                if domain == 2 && !crate::net::ipver::ipv4_enabled() {
                    return -97; // EAFNOSUPPORT
                }
                let net_type = match sock_type {
                    1 => crate::net::socket::SocketType::Tcp,
                    _ => crate::net::socket::SocketType::Udp,
                };
                let socket_id = crate::net::socket::socket_create(net_type);
                // Per socket(2): SOCK_CLOEXEC and SOCK_NONBLOCK in the `type`
                // argument must be applied atomically to the returned fd —
                // POSIX.1-2017 socket(2), same contract as AF_UNIX above.
                crate::syscall::alloc_socket_fd(pid, socket_id, sock_type as u32, cloexec, nonblock)
            } else {
                -22 // EINVAL — unsupported domain
            }
        }
        // 42: connect(sockfd, addr, addrlen)
        42 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen = arg3 as usize;
            if addrlen < 2 || addr_ptr == 0 { return -22; }
            // SMAP bracket — the family read derefs a user pointer.
            let family = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::read_unaligned(addr_ptr as *const u16)
            };

            if family == 1 {
                // AF_UNIX — sockaddr_un { sa_family: u16, sun_path: [u8; 108] }
                if !crate::syscall::is_unix_socket_fd(pid, fd) { return -9; }
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                // SMAP bracket — copy the path bytes into a kernel Vec so the
                // downstream IPC work doesn't hold AC=1.
                let path_owned: alloc::vec::Vec<u8> = if addrlen > 2 {
                    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
                    let s = unsafe { core::slice::from_raw_parts((addr_ptr + 2) as *const u8, (addrlen - 2).min(108)) };
                    s.to_vec()
                } else { return -22; };
                let path_bytes: &[u8] = &path_owned;
                // Strip trailing NUL
                let plen = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                #[cfg(feature = "firefox-test-core")]
                if pid >= 1 {
                    if let Ok(p) = core::str::from_utf8(&path_bytes[..plen]) {
                        crate::serial_println!("[FF/connect] pid={} path={}", pid, p);
                    }
                }
                // Record the connecting client's effective credentials on
                // the new accept-side socket so the server's
                // getsockopt(SO_PEERCRED) returns the client's identity
                // per unix(7) — finding H7 (CWE-287).
                let (cpid, cuid, cgid) = crate::proc::current_creds_lockless();
                let creds = crate::net::unix::PeerCreds { pid: cpid, uid: cuid, gid: cgid };
                crate::net::unix::connect(unix_id, &path_bytes[..plen], creds)
            } else {
                if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                // Runtime address-family gate (see net::ipver).  Belt-and-
                // suspenders for a socket created *before* the family was
                // disabled: connect(2) to a destination in a disabled family
                // returns ENETUNREACH, matching the runtime
                // `net.ipv6.conf.all.disable_ipv6=1` sysctl (the socket stays
                // creatable but egress on it is unreachable).  Note: AF_INET6
                // is the family that matters here — its connect path is not
                // implemented at all, so this also REPLACES the former
                // fake-success stub (which lied "connected" to a dead IPv6
                // address and wedged RFC 6724 Happy-Eyeballs, whose IPv4
                // fallback requires the dead-family connect to FAIL).
                if family == 10 && !crate::net::ipver::ipv6_enabled() {
                    return -101; // ENETUNREACH
                }
                if family == 2 && !crate::net::ipver::ipv4_enabled() {
                    return -101; // ENETUNREACH
                }
                if family == 2 && addrlen >= 16 {
                    // sockaddr_in — SMAP-bracketed copy into kernel-local
                    // bytes so the connect / wait loop below runs without
                    // AC=1.
                    let mut bytes = [0u8; 16];
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::copy_nonoverlapping(addr_ptr as *const u8, bytes.as_mut_ptr(), 16);
                    }
                    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                    let ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
                    match crate::net::socket::socket_connect(socket_id, ip, port) {
                        Ok(()) => {
                            // Per IEEE 1003.1 §connect: only connection-mode
                            // transports (TCP) perform a handshake and may
                            // block.  UDP / SOCK_DGRAM connect(2) is a pure
                            // local-state update — return immediately so
                            // the userspace resolver (musl getaddrinfo etc.)
                            // can move on to sendto.  Sampling the socket
                            // type here avoids waiting on tcp::get_state for
                            // a UDP socket that will never produce one — the
                            // pre-fix path returned -110 ETIMEDOUT after 3 s
                            // for every UDP connect, breaking DNS.
                            let (sock_type, lport) = {
                                let socks = crate::net::socket::SOCKETS.lock();
                                let sock = socks.iter().find(|s| s.id == socket_id);
                                (sock.map(|s| s.socket_type), sock.map(|s| s.local_port))
                            };
                            if sock_type == Some(crate::net::socket::SocketType::Udp) {
                                return 0;
                            }
                            if let Some(lport) = lport {
                                let deadline = crate::arch::x86_64::irq::get_ticks() + 300;
                                loop {
                                    crate::net::poll();
                                    match crate::net::tcp::get_state(lport) {
                                        Some(crate::net::tcp::TcpState::Established) => break,
                                        Some(crate::net::tcp::TcpState::Closed)
                                        | Some(crate::net::tcp::TcpState::TimeWait) => {
                                            return -111; // ECONNREFUSED
                                        }
                                        _ => {}
                                    }
                                    if crate::arch::x86_64::irq::get_ticks() >= deadline {
                                        return -110; // ETIMEDOUT
                                    }
                                    crate::sched::yield_cpu();
                                }
                            }
                            0
                        }
                        Err(_) => -111, // ECONNREFUSED
                    }
                } else if family == 2 {
                    // AF_INET but the sockaddr is too short (addrlen < 16).
                    // connect(2): "EINVAL — ... the address length is invalid."
                    -22 // EINVAL
                } else if family == 10 {
                    // AF_INET6 with IPv6 enabled: the family passed the gate
                    // above, but there is still no IPv6 TCP egress path in the
                    // stack (no handshake), so connect cannot complete.  Return
                    // ENETUNREACH rather than the former fake-success stub — a
                    // truthful "cannot reach" lets an IPv6-first resolver fall
                    // back per RFC 6724 instead of hanging on a dead "connected"
                    // socket.  When real IPv6 egress lands, replace this arm.
                    -101 // ENETUNREACH
                } else {
                    // Unknown / unsupported address family in the sockaddr.
                    // connect(2): "EAFNOSUPPORT — the passed address didn't
                    // have the correct address family in its sa_family field."
                    -97 // EAFNOSUPPORT
                }
            }
        }
        // 43: accept(sockfd, addr, addrlen) — AF_UNIX + AF_INET both real.
        // arg4 carries `flags` for accept4(2): SOCK_CLOEXEC | SOCK_NONBLOCK.
        // Plain accept(2) (#43) leaves arg4 = 0; accept4(2) (#288) forwards it.
        //
        // POSIX.1-2017 §accept: extracts the first connection from the
        // listening socket's pending-connection queue, creates a new
        // socket of the same type and protocol, and returns a new fd
        // referring to that socket.  The original listening socket is
        // unaffected.
        43 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen_ptr = arg3;
            // accept4 flag bits: SOCK_CLOEXEC = 0x80000, SOCK_NONBLOCK = 0x800.
            let cloexec  = (arg4 & 0x80000) != 0;
            let nonblock = (arg4 & 0x00800) != 0;

            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                return match crate::net::unix::accept(unix_id) {
                    peer_id if peer_id >= 0 => {
                        // Allocate an fd for the accepted connected socket.
                        crate::syscall::alloc_unix_socket_fd(pid, peer_id as u64, cloexec, nonblock)
                    }
                    e => e, // EAGAIN or error
                };
            }
            if !crate::syscall::is_socket_fd(pid, fd) { return -9; } // EBADF

            // Snapshot the listener socket's local port + the
            // per-fd non-blocking flag.  The listener socket itself
            // must be Bound and TCP (POSIX returns EINVAL on accept
            // for non-listening or non-stream sockets).
            let listener_id = crate::syscall::get_socket_id(pid, fd);
            let (listener_port, fd_nonblock) = {
                let sockets = crate::net::socket::SOCKETS.lock();
                let sock = match sockets.iter().find(|s| s.id == listener_id) {
                    Some(s) => s,
                    None => return -22, // EINVAL — socket vanished
                };
                if !sock.bound || sock.socket_type != crate::net::socket::SocketType::Tcp {
                    return -22; // EINVAL — listen() requires a bound stream socket
                }
                let fd_nb = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().find(|p| p.pid == pid)
                        .and_then(|p| p.file_descriptors.get(fd).and_then(|f| f.as_ref()))
                        .map(|f| (f.flags & 0x0800) != 0)
                        .unwrap_or(false)
                };
                (sock.local_port, fd_nb)
            };

            // Dequeue one accept-pending child TCB on this listener's
            // local port.  When the pending queue is empty either
            // block (BLOCKing socket) by yielding until the NIC RX
            // path drives a fresh child past 3WHS (RFC 793 §3.4), or
            // return EAGAIN under SOCK_NONBLOCK / O_NONBLOCK.
            //
            // The TCP RX advances connection state directly from the
            // NIC IRQ, so a simple yield+poll loop is sufficient.
            // `net::poll()` also drains other pending events so we
            // don't starve sibling sockets.
            let blocking = !(nonblock || fd_nonblock);
            let (peer_ip, peer_port) = loop {
                if let Some(p) = crate::net::tcp::take_pending_accept(listener_port) {
                    break p;
                }
                if !blocking { return -11; } // EAGAIN
                if signal_pending(pid)       { return -4;  } // EINTR
                crate::net::poll();
                crate::sched::yield_cpu();
            };

            // Materialise the accept-side socket bound to this 4-tuple.
            let child_id = crate::net::socket::socket_create_accepted(
                listener_port, peer_ip, peer_port);

            // Write the peer address back to user space if requested.
            // POSIX permits both `addr` and `addrlen` to be NULL when
            // the caller does not care about the peer name.  When
            // `addrlen` is non-NULL, treat it as input capacity (max
            // bytes to write into `addr`) and overwrite it with the
            // actual sockaddr size produced.
            //
            // SMAP (Intel SDM Vol 3A §4.6): all user-page accesses
            // performed under AC=1 via UserGuard.  Range-validate
            // first so a kernel-VA addr_ptr cannot direct supervisor
            // writes at arbitrary kernel memory (CWE-823) — SMAP's
            // AC=1 guard catches user-page misses but does not catch
            // kernel-VA dereferences.
            if addr_ptr != 0 {
                if addrlen_ptr == 0
                    || !crate::syscall::validate_user_ptr(addrlen_ptr, 4)
                {
                    crate::net::socket::socket_close(child_id);
                    return -14; // EFAULT
                }
                let cap = unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::read_unaligned(addrlen_ptr as *const u32) as usize
                };
                // sockaddr_in: u16 sin_family + u16 sin_port (be) + 4-byte sin_addr + 8 pad = 16.
                const SOCKADDR_IN_LEN: usize = 16;
                let write_bytes = cap.min(SOCKADDR_IN_LEN);
                if write_bytes > 0
                    && !crate::syscall::validate_user_ptr(addr_ptr, write_bytes)
                {
                    crate::net::socket::socket_close(child_id);
                    return -14; // EFAULT
                }
                // Build the sockaddr_in locally then copy.  AF_INET = 2,
                // sin_port network-byte-order, sin_addr is the raw 4-byte
                // big-endian IPv4 address per RFC 791 §3.1.
                let mut buf = [0u8; SOCKADDR_IN_LEN];
                buf[0] = 2;  buf[1] = 0;
                buf[2] = (peer_port >> 8) as u8;
                buf[3] = (peer_port & 0xff) as u8;
                buf[4..8].copy_from_slice(&peer_ip);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    if write_bytes > 0 {
                        core::ptr::copy_nonoverlapping(
                            buf.as_ptr(), addr_ptr as *mut u8, write_bytes);
                    }
                    // POSIX: addrlen out = actual sockaddr length
                    // (always 16 for AF_INET), even when truncated.
                    core::ptr::write_unaligned(
                        addrlen_ptr as *mut u32, SOCKADDR_IN_LEN as u32);
                }
            }

            // Allocate the new fd.  SOCK_STREAM type code = 1.
            crate::syscall::alloc_socket_fd(pid, child_id, 1, cloexec, nonblock)
        }
        // 44: sendto(sockfd, buf, len, flags, addr, addrlen)
        44 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let buf_ptr = arg2 as *const u8;
            let len = arg3 as usize;
            // SMAP bracket — slice materialised under AC=1 because every
            // path below copies (unix::write / socket_send / socket_sendto)
            // reads through `data`.  The downstream net code is kernel-only
            // and will copy the bytes into its own buffers; we don't hold
            // the guard across those calls.  Materialise + immediately
            // copy into a kernel Vec to keep AC=1 scope tight.
            let data_owned: alloc::vec::Vec<u8> = {
                let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
                unsafe { core::slice::from_raw_parts(buf_ptr, len) }.to_vec()
            };
            let data: &[u8] = &data_owned;
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                crate::net::unix::write(unix_id, data)
            } else {
                if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                let addr_ptr = arg5;
                let addrlen = arg6 as usize;
                if addr_ptr != 0 && addrlen >= 16 {
                    let mut bytes = [0u8; 16];
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::copy_nonoverlapping(addr_ptr as *const u8, bytes.as_mut_ptr(), 16);
                    }
                    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
                    // Runtime address-family gate (see net::ipver).  An
                    // explicitly-addressed datagram to a disabled family fails
                    // with ENETUNREACH, matching connect(2) above and the
                    // `net.ipv6.conf.all.disable_ipv6` sysctl — rather than the
                    // former fake-success (`len as i64`) that silently dropped
                    // the datagram and lied a full write to the caller.
                    if (family == 10 && !crate::net::ipver::ipv6_enabled())
                        || (family == 2 && !crate::net::ipver::ipv4_enabled())
                    {
                        return -101; // ENETUNREACH
                    }
                    if family == 2 {
                        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                        let ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
                        match crate::net::socket::socket_sendto(socket_id, ip, port, data) {
                            Ok(n) => n as i64,
                            Err("EPIPE") => -32,
                            Err(_) => -104,
                        }
                    } else if family == 10 {
                        // AF_INET6 with IPv6 enabled but no egress path — same
                        // truthful ENETUNREACH as the connect(2) AF_INET6 arm.
                        -101 // ENETUNREACH
                    } else {
                        // Unsupported address family in the destination.
                        -97 // EAFNOSUPPORT
                    }
                } else {
                    match crate::net::socket::socket_send(socket_id, data) {
                        Ok(n) => n as i64,
                        Err("EPIPE") => -32,
                        Err(_) => -104,
                    }
                }
            }
        }
        // 45: recvfrom(sockfd, buf, len, flags, addr, addrlen)
        //
        // Per IEEE 1003.1 §recvfrom and `recvfrom(2)`: if `addr` is
        // non-NULL the kernel writes the source 4-tuple of the dequeued
        // datagram (UDP) or the connected peer (TCP).  Honours the in/out
        // semantics of `addrlen`: a smaller user buffer truncates the
        // sockaddr_in but `*addrlen` is still set to the unmodified
        // struct size (16) so callers can detect truncation.  When `addr`
        // is NULL the address is silently dropped (RFC 768 / man-page
        // back-compat — many UDP clients pass NULL when they don't care).
        // AF_UNIX SOCK_DGRAM is not implemented yet, so the AF_UNIX path
        // continues to ignore the address out-params.
        45 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let buf_ptr = arg2 as *mut u8;
            let len = arg3 as usize;
            // flags (arg4): MSG_DONTWAIT = 0x40 (per <sys/socket.h>).
            // MSG_PEEK / MSG_WAITALL not yet wired (out of scope here);
            // userspace DNS resolvers (musl getaddrinfo, busybox nslookup)
            // do not pass them on the UDP receive path.
            let flags = arg4;
            let msg_dontwait = (flags & 0x40) != 0;
            let addr_ptr     = arg5;
            let addrlen_ptr  = arg6 as *mut u32;
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                // Per recvfrom(2) / unix(7): a recv on a socket without
                // O_NONBLOCK and without MSG_DONTWAIT MUST block until a
                // message is available rather than returning -EAGAIN on a
                // momentarily-empty ring.  Park (bounded) until the socket is
                // readable; non-blocking fds skip the wait and fall through to
                // the single drain that yields EAGAIN-on-empty unchanged.
                let blocking = !(msg_dontwait || fd_is_nonblocking(pid, fd));
                if let Err(e) = unix_recv_block_wait(unix_id, pid, blocking) {
                    return e;
                }
                // SMAP bracket — `buf` is a user slice; unix::read writes
                // into it.  Bracket spans the call so the writes inside
                // unix::read run with AC=1.
                let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
                crate::net::unix::read(unix_id, buf)
            } else {
                if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                // O_NONBLOCK on the fd makes the call non-blocking even
                // without MSG_DONTWAIT.  Per IEEE 1003.1 §recvfrom the
                // two flag sources are independent and either disables
                // blocking.  Without this gate every DNS resolver call
                // returns 0 immediately (no datagram queued at entry)
                // and userspace mis-reads it as a zero-length datagram,
                // bailing out before the reply ever arrives.
                let fd_nonblock = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().find(|p| p.pid == pid)
                        .and_then(|p| p.file_descriptors.get(fd).and_then(|f| f.as_ref()))
                        .map(|f| (f.flags & 0x0800) != 0)
                        .unwrap_or(false)
                };
                let blocking = !(msg_dontwait || fd_nonblock);
                // For blocking sockets, yield until the socket has data
                // or the receive deadline fires.  3000 ticks (≈30 s) is
                // the upper bound — matches SO_RCVTIMEO's POSIX default
                // (zero = no timeout) cap of "very long" without leaving
                // a zombie syscall pinning the runner forever.  Most
                // DNS resolvers retry within 5 s anyway (RFC 1035 §4.2.1).
                if blocking {
                    let deadline = crate::arch::x86_64::irq::get_ticks() + 3000;
                    // Break on data OR on an orderly peer-FIN EOF.  A blocking
                    // recv on a stream whose peer has sent FIN with an empty
                    // buffer must wake and return 0 (RFC 9293 §3.5) — it would
                    // otherwise spin to the deadline since no data will arrive.
                    while !crate::net::socket::socket_has_data(socket_id)
                        && !crate::net::socket::socket_is_read_closed(socket_id) {
                        if signal_pending(pid) { return -4; } // EINTR
                        crate::net::poll();
                        if crate::arch::x86_64::irq::get_ticks() >= deadline {
                            return -11; // EAGAIN — surfaces as "timed out"
                        }
                        crate::sched::yield_cpu();
                    }
                }
                // MSG_PEEK (0x2): non-destructive probe.  We cannot peek
                // buffered stream bytes without consuming them, but EOF
                // discovery must still work so a peeking reader (e.g. an
                // Available()-style backup that PEEKs before draining) learns
                // the connection is closed: a peek on a FIN'd empty stream
                // returns 0, not -EAGAIN.  When data is buffered, fall through
                // to the normal drain (best-effort: returns the bytes; the
                // peek-non-consume guarantee is not yet wired and no current
                // userspace path PEEKs buffered AF_INET stream data).
                let msg_peek = (flags & 0x2) != 0;
                if msg_peek && crate::net::socket::socket_is_read_closed(socket_id)
                    && !crate::net::socket::socket_has_data(socket_id) {
                    return 0; // orderly shutdown, observed via peek
                }
                // EOF-aware drain: give recvfrom(2) the same peer-FIN
                // discrimination as recvmsg(2) (nr=47).  Per recv(2) /
                // RFC 9293 §3.5: a peer-FIN'd empty stream is an orderly
                // shutdown → return 0; a still-open empty stream is
                // would-block → -EAGAIN.  The kernel poll readiness
                // (POLLIN|POLLHUP) is left faithful; only the recv return
                // is corrected so a level-triggered reactor observes EOF,
                // closes the fd, and stops re-polling it forever.
                // Stream-bounded dequeue: pass the caller's buffer length so
                // excess STREAM bytes stay queued (IEEE 1003.1 §recv); the
                // datagram arm still returns the whole datagram and the
                // `.min(len)` below performs the SOCK_DGRAM truncation.
                match crate::net::socket::socket_recv_status_from(socket_id, len) {
                    Ok((crate::net::socket::RecvOutcome::Data(data), src_ip, src_port)) => {
                        let n = data.len().min(len);
                        if n > 0 {
                            unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, n);
                            }
                        }
                        // Only marshal the source address when the caller
                        // asked for it (both pointers non-NULL) AND we
                        // actually returned a payload.  A zero-byte read
                        // must leave `*addrlen` untouched per POSIX —
                        // the contents of the sockaddr buffer are
                        // unspecified when no message was received.
                        if n > 0 && addr_ptr != 0 && !addrlen_ptr.is_null() {
                            let cap = unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                core::ptr::read(addrlen_ptr)
                            } as usize;
                            // write_sockaddr_in opens its own UserGuard
                            // for the marshalled writes.
                            write_sockaddr_in(addr_ptr, addrlen_ptr, src_ip, src_port, cap);
                        }
                        n as i64
                    }
                    // Orderly peer shutdown (FIN): 0-byte return per recv(2).
                    // Leaves the user address buffer untouched (no message).
                    Ok((crate::net::socket::RecvOutcome::Eof, _, _)) => 0,
                    // Empty queue on an open stream / no datagram: EAGAIN.
                    Ok((crate::net::socket::RecvOutcome::WouldBlock, _, _)) => -11,
                    Err(_) => -11,
                }
            }
        }
        // 46: sendmsg(sockfd, msg, flags) — use single-buffer fast path
        46 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let msghdr_ptr = arg2 as *const u64;
            if msghdr_ptr.is_null() { return -22; }
            // CWE-823: validate msghdr is in user space before dereferencing
            // any field. The msghdr layout (x86_64 Linux ABI) is 56 bytes
            // ending at msg_flags (offset 48–52); ctrl writes touch up to
            // ctrl_ptr + ctrl_len which is validated separately below.
            if !crate::syscall::validate_user_ptr(arg2, 56) { return -14; }
            // SMAP bracket the msghdr field reads (iov_ptr, iov_len).
            let (iov_ptr, iov_len) = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                (core::ptr::read_unaligned(msghdr_ptr.add(2)),  // offset 16
                 core::ptr::read_unaligned(msghdr_ptr.add(3)))  // offset 24
            };
            if iov_ptr == 0 || iov_len == 0 { return 0; }
            if iov_len > 1024 { return -22; } // IOV_MAX per POSIX sendmsg(2)
            if !crate::syscall::validate_user_ptr(iov_ptr, (iov_len as usize).saturating_mul(16)) {
                return -14;
            }
            // Copy the iovec array into kernel memory so the per-iov
            // base/len reads do not need to re-enter user space; this
            // also defangs any TOCTOU between validate and use.
            let iovecs_owned: alloc::vec::Vec<[u64; 2]> = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iov_len as usize).to_vec()
            };
            // SCM_RIGHTS first-byte bind: capture the peer's recv-stream
            // position BEFORE any data iovec of this frame is pushed, so a
            // queued ancillary fd batch binds to the FIRST byte of the frame
            // it accompanies — not its tail.  Per recvmsg(2) / unix(7) /
            // POSIX.1-2017, the ancillary SCM_RIGHTS data is delivered with
            // the message data it accompanies; the receiver's IPC reader
            // parses a frame whose header announces N handles and requires
            // those fds on the SAME recvmsg that first returns the frame's
            // bytes.  Binding to the tail (post-push) withholds the fds until
            // the reader has drained EVERY byte of the frame, which fails when
            // the reader consumes the frame in pieces (e.g. reads the header,
            // sees num_handles>=1, then expects the fds already present) —
            // surfacing as a fatal "needs unreceived descriptors".  The
            // deliver predicate is `recv_consumed >= byte_offset`
            // (syscall/mod.rs scm_dequeue); with byte_offset = the frame's
            // starting recv position, the batch becomes deliverable the
            // instant the reader pops the frame's first byte.  Computed once
            // here (under the unix TABLE lock, briefly) for unix sockets only.
            // Sender's own AF_UNIX socket id (for the writable-gate below).
            let scm_sender_unix_id: u64 = if crate::syscall::is_unix_socket_fd(pid, fd) {
                crate::syscall::get_unix_socket_id(pid, fd)
            } else {
                u64::MAX
            };
            let scm_bind_peer_id: u64 = if scm_sender_unix_id != u64::MAX {
                crate::net::unix::get_peer(scm_sender_unix_id)
            } else {
                u64::MAX
            };
            let scm_bind_offset: u64 = if scm_bind_peer_id != u64::MAX {
                crate::net::unix::enqueue_offset_for(scm_bind_peer_id)
            } else {
                0
            };
            // Whether this frame carries any data bytes — known from the iovec
            // lengths BEFORE the push, so the SCM batch can be queued ahead of
            // the data it accompanies (see the ordering note below).  A frame
            // with at least one non-empty iovec is data-bearing.
            let frame_has_data = iovecs_owned.iter().any(|iov| iov[1] != 0);
            // First-byte-accepted gate for the SCM_RIGHTS batch.  The batch is
            // queued BEFORE the data push (the ordering invariant below), but it
            // must only be queued if at least one byte of THIS frame will be
            // accepted into the peer ring — otherwise the push loop returns
            // -EAGAIN with `total == 0` (nothing queued), the whole sendmsg(2)
            // reports -EAGAIN, and a userspace stream writer retries the entire
            // frame from the start WITH its control message re-attached.  Were
            // the batch queued unconditionally, that retry would enqueue a
            // SECOND batch for the same frame — duplicating the fds on the peer
            // (CWE-675 / a double-delivery of the ancillary descriptors).  A
            // DATA-bearing frame thus queues its batch only when the peer ring
            // has room for >=1 byte (net::unix::writable, the same predicate
            // that gates whether write() returns >0 vs -EAGAIN).  A control-ONLY
            // frame (no data bytes) carries nothing to push and is a 0-byte
            // readable ancillary message in its own right (recvmsg(2), unix(7)
            // SCM_RIGHTS); it is always queued regardless of ring fullness.
            let scm_first_byte_will_land = if !frame_has_data {
                true
            } else if scm_sender_unix_id != u64::MAX {
                crate::net::unix::writable(scm_sender_unix_id)
            } else {
                false
            };
            let mut total = 0usize;
            // ORDERING (race fix): the SCM_RIGHTS batch is queued BEFORE the data
            // bytes are pushed into the peer's recv ring.  The data push and the
            // batch enqueue are separate critical sections (net::unix TABLE lock
            // vs PENDING_SCM lock); if the bytes became readable first, a peer
            // recvmsg(2) could drain the frame's bytes and compute its read cap
            // (scm_next_batch_offset) BEFORE the batch was visible, deliver no
            // fds, and strand the batch past the reader's position — the
            // intermittent "needs unreceived descriptors" on the cross-process
            // channel.  Queuing the batch first (bound to the pre-push offset)
            // guarantees the batch is in PENDING_SCM before any of its
            // accompanying bytes can be read, so the reader's cap always stops at
            // it.  Per recvmsg(2) / unix(7) / POSIX.1-2017 §2.14, the ancillary
            // data is delivered with the data it accompanies.
            // Handle SCM_RIGHTS in msg_control (Unix sockets only).
            // msghdr layout (x86_64): msg_control at byte-offset 32 (u64 index 4),
            // msg_controllen at byte-offset 40 (u64 index 5).
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                // SMAP bracket — read msghdr.msg_control / msg_controllen
                // and the cmsghdr fields under a single guard.
                //
                // CWE-823: ctrl_ptr is read from user-controlled
                // msghdr.msg_control and immediately dereferenced for
                // cmsg_len/level/type.  Like msghdr_ptr itself, it must be
                // range-validated against ctrl_len before any kernel-mode
                // read; otherwise a malicious caller can place a kernel-VA
                // in msg_control and have the kernel splice attacker-named
                // kernel bytes into the SCM_RIGHTS path.  Per sendmsg(2),
                // msg_control is user memory at all times.  SMAP catches
                // user-page accesses without AC=1 but does *not* catch
                // kernel-VA dereferences — only the range check does.
                let (ctrl_ptr, ctrl_len, cmsg_len, cmsg_level, cmsg_type) = unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    let cp = core::ptr::read_unaligned(msghdr_ptr.add(4));
                    let cl = core::ptr::read_unaligned(msghdr_ptr.add(5)) as usize;
                    if cp != 0
                        && cl >= 16
                        && crate::syscall::validate_user_ptr(cp, cl)
                    {
                        let ctrl = cp as *const u8;
                        (cp, cl,
                         core::ptr::read_unaligned(ctrl as *const u64) as usize,
                         core::ptr::read_unaligned((cp + 8)  as *const i32),
                         core::ptr::read_unaligned((cp + 12) as *const i32))
                    } else {
                        // Caller-supplied ctrl_ptr is null / too short / kernel-VA.
                        // Zero out the cmsghdr fields so the guard below treats
                        // this as "no SCM_RIGHTS to deliver" rather than
                        // dereferencing the bad pointer.
                        (0u64, 0usize, 0usize, 0i32, 0i32)
                    }
                };
                // `scm_first_byte_will_land` gate: skip the entire SCM_RIGHTS
                // clone/ref-bump/enqueue when no byte of this data-bearing frame
                // will be accepted (peer ring full).  The push loop will then
                // return -EAGAIN with total==0 and the writer retries the WHOLE
                // frame (cmsg included) — so queuing here would double the batch.
                // Gating before the clone also avoids taking fd references we
                // would otherwise have to release (CWE-772).  A control-only
                // frame always lands (scm_first_byte_will_land == true).
                if ctrl_ptr != 0 && ctrl_len >= 16 && scm_first_byte_will_land {
                    const SOL_SOCKET_I32: i32 = 1;
                    const SCM_RIGHTS_I32: i32 = 1;
                    if cmsg_level == SOL_SOCKET_I32 && cmsg_type == SCM_RIGHTS_I32 && cmsg_len > 16 {
                        let nfds = (cmsg_len.min(ctrl_len) - 16) / 4;
                        let fd_arr = (ctrl_ptr + 16) as *const i32;
                        let sender_fds: Vec<crate::vfs::FileDescriptor> = {
                            let procs = crate::proc::PROCESS_TABLE.lock();
                            if let Some(p) = procs.iter().find(|p| p.pid == pid) {
                                (0..nfds).filter_map(|i| {
                                    // SMAP bracket each fd read.  The
                                    // PROCESS_TABLE lock is held — keep
                                    // the AC=1 region as narrow as
                                    // possible.
                                    let fd_n = unsafe {
                                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                                        core::ptr::read_unaligned(fd_arr.add(i))
                                    } as usize;
                                    if fd_n < p.file_descriptors.len() {
                                        let cloned = p.file_descriptors[fd_n].clone();
                                        // SCM_RIGHTS duplicates the open file
                                        // description into the receiver — the
                                        // passed fd "refers to the same open
                                        // file description as the corresponding
                                        // descriptor in the sending process"
                                        // (unix(7) SCM_RIGHTS, POSIX.1-2017
                                        // §2.14).  Bump the underlying object's
                                        // refcount so that when the sender later
                                        // close(2)s its copy, the shared socket
                                        // /pipe is NOT torn down and the peer is
                                        // not spuriously hung up (CWE-416 — the
                                        // close-resets-slot/shuts-peer path).
                                        // Mirrors the dup(2)/fork(2) inc_ref.
                                        if let Some(ref fdesc) = cloned {
                                            if fdesc.file_type
                                                == crate::vfs::FileType::Socket
                                                && fdesc.flags
                                                    & crate::syscall::UNIX_SOCKET_FLAG != 0
                                            {
                                                crate::net::unix::inc_ref(fdesc.inode);
                                            } else if fdesc.file_type
                                                == crate::vfs::FileType::Pipe
                                                && fdesc.mount_idx == usize::MAX
                                                && fdesc.flags & 0x8000_0000 != 0
                                            {
                                                if fdesc.flags & 1 == 1 {
                                                    crate::ipc::pipe::pipe_add_writer(
                                                        fdesc.inode);
                                                } else {
                                                    crate::ipc::pipe::pipe_add_reader(
                                                        fdesc.inode);
                                                }
                                            } else if fdesc.file_type
                                                == crate::vfs::FileType::RegularFile
                                                && fdesc.mount_idx != usize::MAX
                                            {
                                                // Regular file / memfd: VFS tracks
                                                // inode lifetime by scanning open
                                                // fd tables (unlink-on-last-close),
                                                // but this passed copy is in flight
                                                // in PENDING_SCM and NOT yet in any
                                                // fd table, so the scan cannot see
                                                // it.  Pin the inode so a sender's
                                                // close(2) of its (possibly the
                                                // last named) copy of an unlinked
                                                // memfd cannot free the inode out
                                                // from under the un-received
                                                // descriptor — the Mozilla
                                                // shared-surface fd handoff.
                                                // Balanced by unpin on delivery or
                                                // on drain (scm_drop_fds path).
                                                crate::vfs::pin_inode(
                                                    fdesc.mount_idx, fdesc.inode);
                                            } else if fdesc.file_type
                                                == crate::vfs::FileType::EventFd
                                            {
                                                // The in-flight copy is one more
                                                // reference to the same open file
                                                // description (unix(7) SCM_RIGHTS);
                                                // balanced by the receiver's later
                                                // close(2), or by scm_drop_fds if
                                                // the batch is never received.
                                                crate::ipc::eventfd::inc_ref(
                                                    fdesc.inode);
                                            }
                                        }
                                        cloned
                                    } else { None }
                                }).collect()
                            } else { Vec::new() }
                        };
                        if !sender_fds.is_empty() {
                            let peer_id = scm_bind_peer_id;
                            if peer_id != u64::MAX {
                                // Bind the fd batch so it co-delivers with the
                                // recvmsg that returns the FIRST byte of this
                                // frame — the first-byte-touch delivery contract
                                // (recvmsg(2) / unix(7) / POSIX.1-2017 §2.14:
                                // ancillary data is delivered with the data it
                                // accompanies).  `scm_bind_offset` was captured
                                // BEFORE the data-push loop, so it is the stream
                                // position T where the frame begins.
                                //
                                // The deliver predicate is `recv_consumed >=
                                // byte_offset` (syscall/mod.rs scm_dequeue).
                                // Popping the frame's first byte advances
                                // recv_consumed from T to T+1, so to gate the
                                // batch on "the reader has touched (begun
                                // consuming) this frame" we bind a DATA-bearing
                                // frame to T+1 — deliverable the instant the
                                // first byte is popped, and NOT before any byte
                                // of the frame is read.  A control-only frame
                                // (no data bytes) carries no bytes to touch; it
                                // sits at the stream tail and must be immediately
                                // readable as a 0-byte ancillary message, so it
                                // binds to T (==tail) and the predicate fires at
                                // once.  This keeps the dequeue predicate uniform
                                // (`>=`) while honouring both cases.  `frame_has_data`
                                // is computed from the iovec lengths above (the
                                // batch is queued before the push, so `total` is
                                // not yet known here).
                                let bind_offset = if frame_has_data {
                                    scm_bind_offset + 1
                                } else {
                                    scm_bind_offset
                                };
                                crate::syscall::scm_queue(peer_id, bind_offset, sender_fds);
                                // Wake any poller/epoll_wait parked on the peer
                                // fd so it re-evaluates and discovers the new
                                // readable (ancillary) message immediately,
                                // rather than waiting for the resync floor.
                                // PENDING_SCM and the unix TABLE lock are both
                                // already released here (scm_queue takes only
                                // PENDING_SCM, briefly), so this honours the
                                // drop-the-lock-before-ring discipline.
                                crate::ipc::waitlist::ring_poll_bell_for_obj(
                                    crate::ipc::waitlist::PollBellSource::UnixWrite, peer_id);
                            }
                        }
                    }
                }
            }
            // Push the frame's data bytes AFTER the SCM_RIGHTS batch is queued
            // (see the ordering note above): the batch is now in PENDING_SCM, so
            // the instant these bytes become readable a peer recvmsg(2) will cap
            // its read at the batch and deliver it.  `total` accumulates the
            // bytes accepted by the transport for the syscall return value.
            for iov in &iovecs_owned {
                let base = iov[0] as *const u8;
                let slen = iov[1] as usize;
                if slen == 0 { continue; }
                // SMAP bracket — slice materialises against the user iov
                // buffer; copy into a kernel Vec immediately so the net
                // layer's send (which may take locks / queue) runs
                // outside AC=1.
                let data_owned: alloc::vec::Vec<u8> = {
                    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
                    unsafe { core::slice::from_raw_parts(base, slen) }.to_vec()
                };
                let data: &[u8] = &data_owned;
                if crate::syscall::is_unix_socket_fd(pid, fd) {
                    let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                    match crate::net::unix::write(unix_id, data) {
                        n if n >= 0 => total += n as usize,
                        // Per POSIX.1-2017 send(2)/sendmsg(2): a non-blocking
                        // SOCK_STREAM transmit that has already queued some
                        // bytes must report the COUNT actually queued (a short
                        // write), NOT -EAGAIN — -EAGAIN is reserved for the
                        // case where ZERO bytes could be queued.  net::unix::write
                        // returns -EAGAIN (-11) only when the peer recv ring was
                        // already full (n == 0).  When the ring fills part-way
                        // through this iovec loop, earlier iovecs of THIS frame
                        // (and possibly a leading partial of this iovec) are
                        // already in the ring: `total > 0`.  Returning the raw
                        // -EAGAIN here would discard that `total`, so the userspace
                        // stream writer (which resumes a short write from the
                        // returned byte count and re-sends from frame-start on a
                        // bare -EAGAIN) would re-transmit the already-queued
                        // leading bytes AND re-attach the frame's SCM_RIGHTS
                        // control fds — desynchronising the byte stream and the
                        // ancillary-fd accounting on the peer.  Break and return
                        // the honest short-write count; -EAGAIN is returned only
                        // when nothing at all was queued (total == 0).
                        e if e == -11 && total > 0 => break,
                        e => return e,
                    }
                } else {
                    if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                    let socket_id = crate::syscall::get_socket_id(pid, fd);
                    match crate::net::socket::socket_send(socket_id, data) {
                        Ok(n) => total += n,
                        Err("EPIPE") => return -32,
                        Err(_) => return -104,
                    }
                }
            }
            total as i64
        }
        // 47: recvmsg(sockfd, msg, flags) — via socket_recv / unix::read
        47 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let msghdr_ptr = arg2 as *const u64;
            if msghdr_ptr.is_null() { return -22; }
            // CWE-823: validate msghdr is in user space (see sendmsg above).
            if !crate::syscall::validate_user_ptr(arg2, 56) { return -14; }
            // SMAP bracket the msghdr field reads.
            let (iov_ptr, iov_len) = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                (core::ptr::read_unaligned(msghdr_ptr.add(2)),
                 core::ptr::read_unaligned(msghdr_ptr.add(3)))
            };
            if iov_ptr == 0 || iov_len == 0 { return -22; }
            if iov_len > 1024 { return -22; } // IOV_MAX per POSIX recvmsg(2)
            // Only iov[0] is consumed below, but validate the full iovec array
            // size the caller advertised so a malformed iov_len cannot mask a
            // kernel-address iov_ptr; the dereferenced iov_base is bounded by
            // the cap below and reaches fd_read via socket_recv.
            if !crate::syscall::validate_user_ptr(iov_ptr, (iov_len as usize).saturating_mul(16)) {
                return -14;
            }
            // SMAP-bracketed iov[0] read; we only consume the first element.
            let (dst, cap) = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                let iov = core::slice::from_raw_parts(iov_ptr as *const [u64; 2], 1);
                (iov[0][0] as *mut u8, iov[0][1] as usize)
            };
            let bytes_read: i64;
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                // Per recvmsg(2) / unix(7): a recv on a socket that is not in
                // non-blocking mode (no O_NONBLOCK on the description, no
                // MSG_DONTWAIT in `flags`) MUST block until a message is
                // available rather than returning -EAGAIN on a momentarily-empty
                // recv ring.  recvmsg(2) flags is the third argument (arg3);
                // MSG_DONTWAIT = 0x40 per <sys/socket.h>.  The single-shot
                // read_msg below returns -EAGAIN on an empty ring regardless of
                // mode, so without this gate a blocking recvmsg consumer — such
                // as a SOCK_SEQPACKET request/response broker that loops on
                // recvmsg with no MSG_DONTWAIT and only retries on EINTR —
                // mis-reads the spurious EAGAIN and tears its channel down.
                // The SCM-deliverable promote-to-0 arm below is preserved: a
                // control-only frame is "ready" (unix_recv_ready), so the wait
                // returns Ok and the drain falls into that arm.
                let msg_dontwait = (arg3 & 0x40) != 0;
                let blocking = !(msg_dontwait || fd_is_nonblocking(pid, fd));
                if let Err(e) = unix_recv_block_wait(unix_id, pid, blocking) {
                    return e;
                }
                // Cap the STREAM drain at the next pending SCM_RIGHTS batch
                // boundary so this recvmsg does not consume bytes PAST the
                // stream position where the next fd batch becomes deliverable.
                // `scm_dequeue` (below) hands back exactly ONE batch per
                // recvmsg; a byte-stream reader reads up to a large fixed buffer
                // per call, so without this cap a single recvmsg can drain bytes
                // spanning several fd-bearing frames while only one batch's fds
                // are delivered — the reader then parses a later frame whose
                // descriptors were silently withheld and aborts ("needs
                // unreceived descriptors").  Capping at the next batch offset
                // makes each recvmsg return the bytes up to exactly one fd batch
                // and deliver that batch, then stop — the AF_UNIX stream recv
                // stops at each fd-bearing message boundary (recvmsg(2), unix(7)
                // SCM_RIGHTS: one message's ancillary fds per recv).  Datagram /
                // SEQPACKET reads are message-framed already, so the cap only
                // bites the byte-stream STREAM kind; it never shrinks the read
                // below 1 byte (the next-batch offset is strictly > consumed).
                let eff_cap = if crate::net::unix::kind(unix_id)
                    == crate::net::unix::SockKind::Stream
                {
                    let consumed = crate::net::unix::recv_consumed(unix_id);
                    match crate::syscall::scm_next_batch_offset(unix_id, consumed) {
                        Some(next) => {
                            // next > consumed (guaranteed by the helper); the
                            // gap is the bytes the reader may drain before the
                            // batch at `next` must be delivered on its own recv.
                            let gap = (next - consumed) as usize;
                            cap.min(gap)
                        }
                        None => cap,
                    }
                } else {
                    cap
                };
                // SMAP bracket — read_msg writes through `buf` into user
                // memory.  Held for the call duration; we drop it before
                // the subsequent allocations / table walks below.
                const MSG_TRUNC: u32 = 0x20;
                // recvmsg(2): MSG_CTRUNC indicates that some ancillary control
                // data was discarded because the receiver's `msg_control`
                // buffer was too small.  Independent of MSG_TRUNC (data
                // truncation); both may be set on the same call.
                const MSG_CTRUNC: u32 = 0x8;
                bytes_read = {
                    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
                    let buf = unsafe { core::slice::from_raw_parts_mut(dst, eff_cap) };
                    match crate::net::unix::read_msg(unix_id, buf) {
                        Ok((n, discarded)) => {
                            // Overwrite (not OR) msg_flags — recvmsg(2) man page.
                            let computed: u32 = if discarded > 0 { MSG_TRUNC } else { 0 };
                            unsafe {
                                let flags_ptr = (arg2 + 48) as *mut u32;
                                core::ptr::write_unaligned(flags_ptr, computed);
                            }
                            n as i64
                        }
                        // EAGAIN on an empty data ring is *not* the final
                        // answer when a deliverable SCM_RIGHTS batch is
                        // queued: a control-only ancillary frame (iov_len==0)
                        // is a readable message that recvmsg(2) must return
                        // with 0 data bytes and the cmsg attached (recvmsg(2),
                        // unix(7), POSIX.1-2017 SCM_RIGHTS).  Promote to a
                        // 0-byte success so the SCM-delivery block below runs;
                        // msg_flags clears (no MSG_TRUNC for an empty read).
                        Err(-11) if crate::syscall::has_scm_deliverable(
                            unix_id, crate::net::unix::recv_consumed(unix_id)) =>
                        {
                            unsafe {
                                let flags_ptr = (arg2 + 48) as *mut u32;
                                core::ptr::write_unaligned(flags_ptr, 0u32);
                            }
                            0i64
                        }
                        Err(e) => e,
                    }
                };
                // Deliver pending SCM_RIGHTS fds into receiver's fd table.
                // Bound the batch to the reader's now-current stream position
                // (recv_consumed) so an earlier data-only frame's reader does
                // not pick up a later frame's fds.
                if bytes_read >= 0 {
                    let consumed = crate::net::unix::recv_consumed(unix_id);
                    // Pop the batch together with its bound stream offset so an
                    // un-installed remainder can be re-queued at the SAME offset
                    // (recvmsg(2) / cmsg(3): control data that does not fit is
                    // not dropped — MSG_CTRUNC is raised and the unfitting fds
                    // remain available to a subsequent larger-buffer recvmsg).
                    if let Some((batch_off, mut scm_fds)) =
                        crate::syscall::scm_dequeue_with_offset(unix_id, consumed)
                    {
                        let nfds = scm_fds.len();
                        // Read the receiver's msg_control geometry up front so we
                        // know how many descriptors actually fit BEFORE moving any
                        // into the fd table.  cmsg(3): a single SCM_RIGHTS cmsg of
                        // n fds occupies `CMSG_SPACE(n*4)` = 16 (cmsghdr) + n*4
                        // bytes (we lay the fd array immediately after the 16-byte
                        // header with no extra alignment padding, matching the
                        // CMSG_FIRSTHDR/CMSG_DATA offsets glibc & musl compute).
                        let (ctrl_ptr, ctrl_len) = unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            (core::ptr::read_unaligned(msghdr_ptr.add(4)),
                             core::ptr::read_unaligned(msghdr_ptr.add(5)) as usize)
                        };
                        // How many fds fit: floor((ctrl_len - 16) / 4), clamped to
                        // the batch size and to 0 when ctrl_len < 16.  A ctrl_ptr
                        // of 0, or a range that fails user-pointer validation, is
                        // treated as "nothing fits" so the whole batch is re-queued
                        // and MSG_CTRUNC is raised.
                        let mut fits = ((ctrl_len.saturating_sub(16)) / 4).min(nfds);
                        // `validate_user_ptr` is bypassed inside a
                        // KernelDispatchGuard (in-kernel test driver passing
                        // kernel-VA buffers); in production it is the only
                        // defence against a kernel-VA in msg_control directing
                        // a supervisor write — see CWE-823 note below.
                        let ctrl_ok = ctrl_ptr != 0
                            && fits > 0
                            && (crate::syscall::user_ptr_check_bypassed()
                                || crate::syscall::validate_user_ptr(ctrl_ptr, 16 + fits * 4));
                        if ctrl_ptr == 0 || !ctrl_ok {
                            fits = 0;
                        }
                        // Split off the descriptors that will NOT be installed on
                        // this call; they are re-queued at the batch's original
                        // stream offset so a follow-up recvmsg adopts them.
                        let remainder: Vec<crate::vfs::FileDescriptor> =
                            scm_fds.split_off(fits);
                        // Regular-file / memfd descriptors were pinned at enqueue
                        // (PENDING_SCM holds an inode reference invisible to the
                        // VFS fd-table scan).  Once installed in the receiver's
                        // fd table below, the slot itself keeps the inode alive,
                        // so the in-flight pin can be released.  Snapshot the
                        // (mount_idx, inode) pairs for the INSTALLED prefix only —
                        // the re-queued remainder keeps its enqueue-time pin.
                        let to_unpin: Vec<(usize, u64)> = scm_fds.iter()
                            .filter(|f| f.file_type == crate::vfs::FileType::RegularFile
                                        && f.mount_idx != usize::MAX)
                            .map(|f| (f.mount_idx, f.inode))
                            .collect();
                        // Allocate fds in the receiver's process for the prefix.
                        let new_fd_nums: Vec<i32> = {
                            let mut procs = crate::proc::PROCESS_TABLE.lock();
                            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                                scm_fds.into_iter().map(|fdesc| {
                                    // Find free slot.
                                    let slot = p.file_descriptors.iter()
                                        .position(|e| e.is_none())
                                        .unwrap_or(p.file_descriptors.len());
                                    if slot == p.file_descriptors.len() {
                                        p.file_descriptors.push(Some(fdesc));
                                    } else {
                                        p.file_descriptors[slot] = Some(fdesc);
                                    }
                                    slot as i32
                                }).collect()
                            } else { Vec::new() }
                        };
                        // Balance the enqueue-time pin now that the fd-table slot
                        // holds the reference (PROCESS_TABLE lock released above).
                        for (m, ino) in to_unpin {
                            crate::vfs::unpin_inode(m, ino);
                        }
                        // Re-queue the un-installed remainder at the SAME stream
                        // offset the batch was dequeued from (recvmsg(2) /
                        // cmsg(3): descriptors that did not fit are NOT orphaned —
                        // CWE-772).  Keeping the original byte_offset preserves the
                        // first-byte-touch delivery contract so the next recvmsg
                        // with a larger control buffer adopts them.
                        if !remainder.is_empty() {
                            crate::syscall::scm_queue(unix_id, batch_off, remainder);
                        }
                        // The control buffer truncated the batch (either some fds
                        // did not fit, or ctrl_ptr was 0 / rejected with nfds > 0):
                        // set MSG_CTRUNC.  OR it into the existing msg_flags so the
                        // MSG_TRUNC data-truncation bit written by the data path
                        // above is preserved — both can co-occur (recvmsg(2)).
                        if new_fd_nums.len() < nfds {
                            unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                let flags_ptr = (arg2 + 48) as *mut u32;
                                let cur = core::ptr::read_unaligned(flags_ptr);
                                core::ptr::write_unaligned(flags_ptr, cur | MSG_CTRUNC);
                            }
                        }
                        // Write the SCM_RIGHTS cmsghdr for the INSTALLED prefix.
                        // All reads/writes here target user memory — single SMAP
                        // guard spanning the whole block.
                        //
                        // CWE-823: ctrl_ptr is read from user-controlled
                        // msghdr.msg_control and is the destination of kernel
                        // writes below.  The span actually written
                        // (`16 + fits*4`) was range-validated above
                        // (`ctrl_ok`); we never write past it.  SMAP catches the
                        // missing-AC=1 case for user pages; the range check is the
                        // only line of defence against a kernel-VA in msg_control.
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            if !new_fd_nums.is_empty() {
                                // ctrl_ok held when fits>0, so the span below was
                                // validated; cmsg_len = CMSG_LEN(fits*4) = 16 + n*4.
                                let written = 16 + new_fd_nums.len() * 4;
                                core::ptr::write_unaligned(ctrl_ptr as *mut u64, written as u64);
                                core::ptr::write_unaligned((ctrl_ptr + 8)  as *mut i32, 1i32); // SOL_SOCKET
                                core::ptr::write_unaligned((ctrl_ptr + 12) as *mut i32, 1i32); // SCM_RIGHTS
                                for (i, &new_fd) in new_fd_nums.iter().enumerate() {
                                    core::ptr::write_unaligned((ctrl_ptr + 16 + i as u64 * 4) as *mut i32, new_fd);
                                }
                                // msg_controllen = bytes actually written.
                                core::ptr::write_unaligned(msghdr_ptr.add(5) as *mut u64, written as u64);
                            } else if ctrl_ptr != 0 {
                                // Nothing installed (buffer too small for even one
                                // fd, or ctrl_ptr rejected): no cmsg written,
                                // CMSG_FIRSTHDR()==NULL.  msg_controllen = 0;
                                // MSG_CTRUNC was set above.  The msghdr_ptr was
                                // user-range-validated at the top of the arm, so
                                // this single field write is safe even when
                                // ctrl_ptr itself was rejected.
                                core::ptr::write_unaligned(msghdr_ptr.add(5) as *mut u64, 0u64);
                            }
                        }
                    } else {
                        // No SCM to deliver — set msg_controllen to 0.
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            let ctrl_ptr = core::ptr::read_unaligned(msghdr_ptr.add(4));
                            if ctrl_ptr != 0 {
                                core::ptr::write_unaligned(msghdr_ptr.add(5) as *mut u64, 0u64);
                            }
                        }
                    }
                }
            } else {
                if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                // msghdr.msg_name / msg_namelen (x86_64 ABI): msg_name is the
                // first 8-byte word (offset 0), msg_namelen is the socklen_t at
                // offset 8 (low 32 bits of the second word).  recvmsg(2): on a
                // datagram socket the source address of the received datagram
                // is stored in msg_name (when non-NULL) and msg_namelen is set
                // to the size of the stored address.
                let (name_ptr, name_cap) = unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    (core::ptr::read_unaligned(msghdr_ptr.add(0)),
                     core::ptr::read_unaligned(msghdr_ptr.add(1)) as u32 as usize)
                };
                if crate::net::socket::socket_is_udp(socket_id) {
                    // Datagram path.  Use the source-address-bearing receive so
                    // the reply's origin can be marshalled into msg_name — this
                    // is REQUIRED by userspace DNS resolvers (RFC 1035 §4.2.1,
                    // DNS over UDP:53) that validate the reply's source against
                    // the configured nameserver before accepting it; without
                    // the source, every reply is dropped and getaddrinfo(3)
                    // times out.  A datagram socket has no orderly-EOF concept,
                    // so an empty result is WouldBlock → EAGAIN per recvmsg(2).
                    bytes_read = match crate::net::socket::socket_recvfrom(socket_id) {
                        Ok((data, src_ip, src_port)) => {
                            if data.is_empty() {
                                -11 // EAGAIN
                            } else {
                                let n = data.len().min(cap);
                                unsafe {
                                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                                    core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n);
                                }
                                // Marshal the datagram source into msg_name when
                                // the caller provided a buffer.  write_sockaddr_in
                                // sets sin_family=AF_INET, sin_port=htons(src_port),
                                // sin_addr=src_ip and writes msg_namelen=16.  When
                                // msg_name is NULL the address is dropped
                                // (recvmsg(2)): leave msg_namelen untouched.
                                if name_ptr != 0 {
                                    // msg_namelen is the socklen_t at byte
                                    // offset 8 of the user msghdr (arg2 base).
                                    let namelen_ptr = (arg2 + 8) as *mut u32;
                                    write_sockaddr_in(name_ptr, namelen_ptr,
                                                      src_ip, src_port, name_cap);
                                }
                                n as i64
                            }
                        }
                        Err(_) => -11, // EAGAIN
                    };
                } else {
                    // Connection-mode (TCP) path.  The source is the fixed
                    // connected peer, so per recvmsg(2) we leave msg_name
                    // untouched (a stream socket reports no per-message source).
                    // Per recvmsg(2) / IEEE 1003.1 §recv: on a non-blocking
                    // socket an empty receive queue must return -1/EAGAIN, while
                    // an orderly peer shutdown (EOF) returns 0.  Collapsing both
                    // to 0 (the prior `Ok(empty) => 0`) lied to the caller: a
                    // polled IPC reactor read the 0 as a readable edge and
                    // re-issued recvmsg in a tight loop, never yielding.  Use the
                    // status-aware recv so the two cases get their correct
                    // returns (WouldBlock → -EAGAIN, Eof → 0).
                    // Bounded by the iovec capacity: excess stream bytes
                    // remain queued for the next recvmsg (IEEE 1003.1 §recv).
                    bytes_read = match crate::net::socket::socket_recv_status(socket_id, cap) {
                        Ok(crate::net::socket::RecvOutcome::Data(data)) => {
                            let n = data.len().min(cap);
                            unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n);
                            }
                            n as i64
                        }
                        Ok(crate::net::socket::RecvOutcome::Eof) => 0,
                        Ok(crate::net::socket::RecvOutcome::WouldBlock) => -11, // EAGAIN
                        Err(_) => -11,
                    };
                }
            }
            bytes_read
        }
        // 48: shutdown(sockfd, how) — half-close per IEEE 1003.1 §shutdown
        // and RFC 793 §3.5.  `how` ∈ {SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2}.
        // Returns 0 on success, -EBADF for a non-socket fd, -ENOTCONN for
        // an unconnected stream socket, -EINVAL on bad `how`.
        48 => {
            let pid = crate::proc::current_pid_lockless();
            let fd  = arg1 as usize;
            let how = arg2 as i32;
            if how < 0 || how > 2 { return -22; }
            let want_rd = how == 0 || how == 2;
            let want_wr = how == 1 || how == 2;
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                crate::net::unix::shutdown(unix_id, want_rd, want_wr)
            } else if crate::syscall::is_socket_fd(pid, fd) {
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                crate::net::socket::socket_shutdown(socket_id, how) as i64
            } else {
                -9 // EBADF
            }
        }
        // 49: bind(sockfd, addr, addrlen)
        49 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen = arg3 as usize;
            if addrlen < 2 || addr_ptr == 0 { return -22; }
            // SMAP bracket family read.
            let family = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::read_unaligned(addr_ptr as *const u16)
            };
            if family == 1 {
                // AF_UNIX — sockaddr_un
                if !crate::syscall::is_unix_socket_fd(pid, fd) { return -9; }
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                // SMAP-bracketed copy into kernel Vec.
                let path_owned: alloc::vec::Vec<u8> = if addrlen > 2 {
                    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
                    unsafe { core::slice::from_raw_parts((addr_ptr + 2) as *const u8, (addrlen - 2).min(108)) }.to_vec()
                } else { return -22; };
                let path_bytes: &[u8] = &path_owned;
                let plen = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                crate::net::unix::bind(unix_id, &path_bytes[..plen])
            } else if family == 2 && addrlen >= 8 {
                if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                let socket_id = crate::syscall::get_socket_id(pid, fd);
                let mut bytes = [0u8; 8];
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(addr_ptr as *const u8, bytes.as_mut_ptr(), 8);
                }
                let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                match crate::net::socket::socket_bind(socket_id, port) {
                    Ok(()) => 0,
                    Err(_) => -98, // EADDRINUSE
                }
            } else if family == 10 {
                // AF_INET6 bind.  A bind only sets local state (no egress), so
                // when IPv6 is enabled we accept it (the port lives in the same
                // local table — IPv6/IPv4 distinction is moot for our SLIRP
                // single-host setup).  When IPv6 is disabled the family is
                // unsupported, so report EAFNOSUPPORT per bind(2) rather than
                // faking success.
                if !crate::net::ipver::ipv6_enabled() {
                    return -97; // EAFNOSUPPORT
                }
                if addrlen >= 8 {
                    if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
                    let socket_id = crate::syscall::get_socket_id(pid, fd);
                    // sockaddr_in6: sin6_port lives at offset 2 (same as
                    // sockaddr_in), so the local port read is identical.
                    let mut bytes = [0u8; 8];
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::copy_nonoverlapping(addr_ptr as *const u8, bytes.as_mut_ptr(), 8);
                    }
                    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                    match crate::net::socket::socket_bind(socket_id, port) {
                        Ok(()) => 0,
                        Err(_) => -98, // EADDRINUSE
                    }
                } else {
                    -22 // EINVAL — sockaddr too short for an AF_INET6 bind
                }
            } else {
                // Unsupported address family in the bind sockaddr.
                -97 // EAFNOSUPPORT
            }
        }
        // 50: listen(sockfd, backlog)
        50 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            if crate::syscall::is_unix_socket_fd(pid, fd) {
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                crate::net::unix::listen(unix_id)
            } else {
                0 // AF_INET stub
            }
        }
        // 51: getsockname(sockfd, addr, addrlen)
        //
        // Per IEEE 1003.1 §getsockname: writes the locally-bound 4-tuple
        // for AF_INET sockets, or the bound path for AF_UNIX.  An unbound
        // AF_INET socket reports 0.0.0.0:0 with success.  The caller's
        // `*addrlen` is read as the buffer cap (truncation only) and on
        // return holds the unmarshalled struct's full size.
        51 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen_ptr = arg3 as *mut u32;
            if addr_ptr == 0 || addrlen_ptr.is_null() { return -22; }
            let cap = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::read(addrlen_ptr)
            } as usize;

            if crate::syscall::is_unix_socket_fd(pid, fd) {
                // AF_UNIX sockaddr_un — minimal: family=1, empty path.
                // Suffices for socketpair() peers and unnamed sockets;
                // bind()-ed paths could be plumbed through a unix
                // accessor in a follow-on phase.
                let want = 2usize;
                let mut tmp = [0u8; 110];
                tmp[0] = 1; // AF_UNIX
                let n = cap.min(want);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(tmp.as_ptr(), addr_ptr as *mut u8, n);
                    core::ptr::write(addrlen_ptr, want as u32);
                }
                return 0;
            }
            if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
            let socket_id = crate::syscall::get_socket_id(pid, fd);
            let (ip, port) = crate::net::socket::socket_local_addr(socket_id);
            write_sockaddr_in(addr_ptr, addrlen_ptr, ip, port, cap);
            0
        }
        // 52: getpeername(sockfd, addr, addrlen)
        //
        // Per IEEE 1003.1 §getpeername: writes the connected peer's
        // 4-tuple, or returns ENOTCONN (-107) when the socket is not
        // connected.  AF_UNIX peer reporting mirrors getsockname's
        // unnamed-socket reply.
        52 => {
            let pid = crate::proc::current_pid_lockless();
            let fd = arg1 as usize;
            let addr_ptr = arg2;
            let addrlen_ptr = arg3 as *mut u32;
            if addr_ptr == 0 || addrlen_ptr.is_null() { return -22; }
            let cap = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::read(addrlen_ptr)
            } as usize;

            if crate::syscall::is_unix_socket_fd(pid, fd) {
                // Unconnected AF_UNIX → ENOTCONN.  Connected AF_UNIX
                // sockets without a bound path report family=1,
                // empty path (matches Linux for unnamed peers).
                let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                if crate::net::unix::state(unix_id) != crate::net::unix::UnixState::Connected {
                    return -107; // ENOTCONN
                }
                let want = 2usize;
                let mut tmp = [0u8; 110];
                tmp[0] = 1;
                let n = cap.min(want);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(tmp.as_ptr(), addr_ptr as *mut u8, n);
                    core::ptr::write(addrlen_ptr, want as u32);
                }
                return 0;
            }
            if !crate::syscall::is_socket_fd(pid, fd) { return -9; }
            let socket_id = crate::syscall::get_socket_id(pid, fd);
            match crate::net::socket::socket_peer_addr(socket_id) {
                Some((ip, port)) => {
                    write_sockaddr_in(addr_ptr, addrlen_ptr, ip, port, cap);
                    0
                }
                None => -107, // ENOTCONN
            }
        }
        // 53: socketpair(domain, type, protocol, sv[2]) — AF_UNIX loopback pair.
        //
        // Per `man 2 socketpair` / `man 7 unix`:
        //   `type` is `sock_type | flags`.
        //     - sock_type & 0xff selects the kind: SOCK_STREAM=1,
        //       SOCK_SEQPACKET=5 (others currently rejected).
        //     - SOCK_CLOEXEC  (0o2000000 = 0x80000) sets FD_CLOEXEC on both fds.
        //     - SOCK_NONBLOCK (0o4000    = 0x800)   sets O_NONBLOCK on both fds.
        //   Unknown sock_type → -EPROTONOSUPPORT (-93).
        //
        // SEQPACKET preserves message boundaries: a recv of N bytes returns at
        // most one full sender-side message and discards any tail that does
        // not fit (the in-kernel net::unix layer enforces this via per-message
        // length records).
        53 => {
            let domain      = arg1 as u32;
            let type_arg    = arg2;
            let sock_type   = type_arg & 0xff;
            let cloexec     = (type_arg & 0x80000) != 0;
            let nonblock    = (type_arg & 0x00800) != 0;
            let sv_ptr      = arg4 as *mut u32;
            if sv_ptr.is_null() { return -22; }
            if domain != 1 {
                // Only AF_UNIX socketpair is implemented.  POSIX permits
                // -EAFNOSUPPORT for unknown families; -EOPNOTSUPP for
                // unsupported family/type combinations.  Mozilla expects an
                // unsupported-domain error; return -EAFNOSUPPORT (-97).
                return -97;
            }
            // Validate sock_type.  Reject everything but STREAM and SEQPACKET
            // for now — DGRAM, RAW, RDM are not implemented for AF_UNIX.
            let kind = match sock_type {
                1 => crate::net::unix::SockKind::Stream,
                5 => crate::net::unix::SockKind::SeqPacket,
                _ => return -93, // EPROTONOSUPPORT
            };
            // Reject any unknown bits in `type` (Linux ignores them, but
            // surfacing rather than silently dropping aids debugging; the
            // common known bits are SOCK_CLOEXEC and SOCK_NONBLOCK only).
            // We accept those plus the type field; anything else passes
            // through silently to match Linux leniency.
            let pid = crate::proc::current_pid_lockless();
            // Both halves of a socketpair belong to the same process per
            // socketpair(2); record its effective credentials on both so
            // SO_PEERCRED on either end identifies the creator (unix(7)).
            let (cpid, cuid, cgid) = crate::proc::current_creds_lockless();
            let creds = crate::net::unix::PeerCreds { pid: cpid, uid: cuid, gid: cgid };
            let (a, b) = crate::net::unix::socketpair(kind, creds);
            if a == u64::MAX { return -24; }
            let fd_a = crate::syscall::alloc_unix_socket_fd(pid, a, cloexec, nonblock);
            if fd_a < 0 {
                crate::net::unix::close(a);
                crate::net::unix::close(b);
                return fd_a;
            }
            let fd_b = crate::syscall::alloc_unix_socket_fd(pid, b, cloexec, nonblock);
            if fd_b < 0 {
                // Best-effort cleanup of fd_a's slot before propagating EMFILE.
                {
                    let mut procs = crate::proc::PROCESS_TABLE.lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                        if let Some(slot) = p.file_descriptors.get_mut(fd_a as usize) {
                            *slot = None;
                        }
                    }
                }
                crate::net::unix::close(a);
                crate::net::unix::close(b);
                return fd_b;
            }
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::write(sv_ptr,       fd_a as u32);
                core::ptr::write(sv_ptr.add(1), fd_b as u32);
            }
            0
        }
        // 54: setsockopt(sockfd, level, optname, optval, optlen)
        54 => {
            let pid   = crate::proc::current_pid_lockless();
            let fd    = arg1 as usize;
            let level = arg2;
            let opt   = arg3;
            let val   = if arg4 != 0 { unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::read_unaligned(arg4 as *const u32)
            } }
                        else         { 0u32 };
            if crate::syscall::is_socket_fd(pid, fd) {
                let sid = crate::syscall::get_socket_id(pid, fd);
                crate::net::socket::socket_setsockopt(sid, level, opt, val) as i64
            } else {
                0 // AF_UNIX: ignore (no per-socket options tracked yet)
            }
        }
        // 55: getsockopt(sockfd, level, optname, optval, optlen)
        55 => {
            let pid    = crate::proc::current_pid_lockless();
            let fd     = arg1 as usize;
            let level  = arg2;
            let opt    = arg3;
            let optval = arg4 as *mut u32;
            let optlen = arg5 as *mut u32;
            // Check AF_UNIX FIRST — unix socket fds also have the
            // 0x4000_0000 socket flag set, so is_socket_fd returns true
            // for them.  But TCP/UDP socket_getsockopt returns 0 when the
            // unix socket ID isn't found, causing Firefox's
            // CHECK(buf_len > 0) to ABORT.
            let val = if crate::syscall::is_unix_socket_fd(pid, fd) {
                const SOL_SOCKET:  u64 = 1;
                const SO_TYPE:     u64 = 3;
                const SO_RCVBUF:   u64 = 8;
                const SO_SNDBUF:   u64 = 7;
                const SO_ERROR:    u64 = 4;
                const SO_PEERCRED: u64 = 17;
                match (level, opt) {
                    (SOL_SOCKET, SO_TYPE)   => 1,  // SOCK_STREAM
                    // Report the AF_UNIX send/recv buffer sizes as the actual
                    // usable capacity of this transport's per-end recv ring
                    // (net::unix::buf_capacity()).  Per socket(7), SO_SNDBUF is
                    // the kernel's send-buffer size; a length-prefixed IPC stream
                    // writer queries it to size each sendmsg(2) so it never offers
                    // more than the transport can atomically accept.  Advertising
                    // a value larger than the ring (the previous 131072 vs a
                    // 32 KiB ring) makes such a writer offer a >ring frame in one
                    // call, which can only be partially queued — needlessly
                    // forcing the partial-write resume path on every large frame.
                    (SOL_SOCKET, SO_RCVBUF) => crate::net::unix::buf_capacity() as u32,
                    (SOL_SOCKET, SO_SNDBUF) => crate::net::unix::buf_capacity() as u32,
                    (SOL_SOCKET, SO_ERROR)  => 0,
                    (SOL_SOCKET, SO_PEERCRED) => {
                        // Return struct ucred { pid: u32, uid: u32, gid: u32 } = 12 bytes.
                        //
                        // Per unix(7) SO_PEERCRED: "Returns the credentials
                        // of the foreign process connected to this socket."
                        // The foreign process is identified by the *peer*
                        // endpoint's recorded creator credentials (captured
                        // at socket(2)/socketpair(2)/connect(2) time).  The
                        // pre-PR behaviour returned the calling process's
                        // own pid, which is an authentication bypass for
                        // every IPC protocol that uses SO_PEERCRED as a
                        // peer identifier (D-Bus auth, sandbox brokers) —
                        // finding H7 of the 2026-05-16 audit, CWE-287
                        // (Improper Authentication).
                        let unix_id = crate::syscall::get_unix_socket_id(pid, fd);
                        let peer = crate::net::unix::peer_creds(unix_id)
                            .unwrap_or(crate::net::unix::PeerCreds { pid: 0, uid: 0, gid: 0 });
                        if !crate::syscall::validate_user_ptr(optval as u64, 12) {
                            return -14; // EFAULT
                        }
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            let p = optval as *mut u8;
                            core::ptr::write_unaligned(p as *mut u32, peer.pid as u32);
                            core::ptr::write_unaligned(p.add(4) as *mut u32, peer.uid);
                            core::ptr::write_unaligned(p.add(8) as *mut u32, peer.gid);
                        }
                        if !optlen.is_null() {
                            if !crate::syscall::validate_user_ptr(optlen as u64, 4) {
                                return -14;
                            }
                            unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                core::ptr::write_unaligned(optlen, 12u32);
                            }
                        }
                        return 0i64;
                    }
                    _ => 0,
                }
            } else if crate::syscall::is_socket_fd(pid, fd) {
                let sid = crate::syscall::get_socket_id(pid, fd);
                crate::net::socket::socket_getsockopt(sid, level, opt)
            } else {
                // Unknown fd type — return sensible defaults
                const SOL_SOCKET:  u64 = 1;
                const SO_TYPE:     u64 = 3;
                const SO_RCVBUF:   u64 = 8;
                const SO_SNDBUF:   u64 = 7;
                match (level, opt) {
                    (SOL_SOCKET, SO_TYPE)   => 1,
                    (SOL_SOCKET, SO_RCVBUF) => 87380,
                    (SOL_SOCKET, SO_SNDBUF) => 131072,
                    _ => 0,
                }
            };
            // SMAP bracket — both writes target user pointers.
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                if !optval.is_null() { core::ptr::write(optval, val); }
                if !optlen.is_null() { core::ptr::write(optlen, 4u32); }
            }
            0
        }
        // 56: clone(flags, stack, parent_tid, child_tid, tls)
        // Linux x86-64 clone ABI: rdi=flags, rsi=stack, rdx=ptid, r10=ctid, r8=tls
        // In our dispatch: arg1=rdi, arg2=rsi, arg3=rdx, arg4=r10, arg5=r8
        56 => {
            let flags = arg1;
            let new_stack = arg2;
            let tls = arg5;   // r8 → arg5 (NOT arg4 which is ctid/r10)
            const CLONE_THREAD: u64 = 0x00010000;
            const CLONE_VM:     u64 = 0x00000100;
            const CLONE_SETTLS: u64 = 0x00080000;
            if flags & CLONE_THREAD != 0 && flags & CLONE_VM != 0 {
                // pthread_create-style clone: new thread in same address space.
                let user_rip = unsafe { crate::syscall::get_user_rip() };
                let tls_val = if flags & CLONE_SETTLS != 0 { tls } else { 0 };
                let pid = crate::proc::current_pid_lockless();
                let parent_tidptr = arg3; // rdx = parent_tid
                let child_tidptr  = arg4; // r10 = child_tid
                match crate::proc::usermode::create_user_thread(pid, user_rip, new_stack, tls_val, 0, 0) {
                    Some(tid) => {
                        crate::serial_println!("[CLONE] Thread TID {} spawned in PID {}", tid, pid);
                        // CLONE-ARGS-DIAG: snapshot pthread args at clone time.
                        // Per upstream musl libc x86_64 __clone, before the
                        // syscall the wrapper does `and $-16,%rsi ; sub $8,%rsi ;
                        // mov %rcx,(%rsi)`, so the kernel-visible `new_stack`
                        // (= the rsi value at syscall entry) already points AT
                        // the slot containing the args-struct pointer.  The
                        // child then does `pop %rdi ; call *%r9` — popping the
                        // args pointer into %rdi (SysV arg0) and calling the
                        // static start helper that was placed in %r9 before
                        // the syscall.  Therefore the args-struct VA is read
                        // at `*new_stack`, not `*(new_stack - 8)`.  See AMD64
                        // SysV ABI §3.4 + POSIX pthread_create(3) + clone(2).
                        #[cfg(feature = "clone-args-diag")]
                        if new_stack != 0 {
                            let args_va = unsafe {
                                let _g = crate::arch::x86_64::smap::UserGuard::new();
                                if crate::syscall::validate_user_ptr(new_stack, 8) {
                                    core::ptr::read_unaligned(new_stack as *const u64)
                                } else { 0 }
                            };
                            crate::subsys::linux::clone_args_diag::record_clone_args(
                                pid as u32, tid as u32, flags, args_va, 0, 0,
                            );
                        }

                        // CLONE_CHILD_SETTID: write TID into child's TCB tid field.
                        const CLONE_CHILD_SETTID: u64 = 0x01000000;
                        if flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 {
                            unsafe { crate::syscall::write_u32_to_user_current(child_tidptr, tid as u32); }
                        }
                        const CLONE_PARENT_SETTID: u64 = 0x00100000;
                        if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
                            unsafe { crate::syscall::write_u32_to_user_current(parent_tidptr, tid as u32); }
                        }
                        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
                        if flags & CLONE_CHILD_CLEARTID != 0 && child_tidptr != 0 {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid as u64) {
                                t.clear_child_tid = child_tidptr;
                            }
                        }

                        tid as i64
                    }
                    None => -11, // EAGAIN
                }
            } else if flags & (CLONE_VM as u64) != 0 {
                // CLONE_VM without CLONE_THREAD = vfork-/posix_spawn-style.
                // CLONE_VM means SHARED address space per clone(2): the child
                // runs in the parent's memory.  glibc uses this for vfork():
                //   clone(CLONE_VM | CLONE_VFORK | SIGCHLD)
                // and for the posix_spawn(3) fast-path.  The child must only
                // call execve(2) or _exit(2); intermediate writes to shared
                // memory (e.g. `args.err = errno`) are observable to the parent.
                let is_vfork = flags & CLONE_VFORK != 0;
                let parent_tid = crate::proc::current_tid();
                let pid = crate::proc::current_pid_lockless();
                crate::serial_println!("[VFORK] pid={} flags={:#x} vfork={} parent_tid={} new_stack={:#x} tls={:#x}",
                    pid, flags, is_vfork, parent_tid, new_stack, tls);

                // Share the parent's CR3 directly (no copy-on-write).  The
                // child gets its own kernel stack but uses the parent's user
                // address space until execve(2) installs a new one.
                let parent_regs = crate::syscall::read_fork_user_regs();
                let child_tidptr = arg4; // r10 = ctid
                match crate::proc::fork_process_share_vm(pid, parent_tid, &parent_regs) {
                    Some((child_pid, child_tid)) => {
                        crate::serial_println!("[VFORK] child PID {} TID {} created (shared VM)", child_pid, child_tid);

                        // If the caller passed a `new_stack`, the conventional
                        // pattern is libc's `__clone` having pushed the
                        // helper-fn `arg` to `*(new_stack-8)`.  POSIX
                        // `vfork(2)` and `clone(2)` both leave the parent's
                        // address space writable through the child, so a
                        // sloppy or short caller-supplied stack can have the
                        // child overflow it into the parent's frame.  The
                        // canonical `posix_spawn(3)` pattern in some libc
                        // implementations is a small `char stack[1024+PATH_MAX]`
                        // local of the parent's `posix_spawn()` frame; the
                        // helper chain (`__libc_sigaction` loop ->
                        // `pthread_sigmask` -> `execve`) can easily push more
                        // than 5 KiB and overflow downward.  When
                        // SSP-instrumented callers (libxul) sit on the parent
                        // stack, the child's overflow clobbers their saved
                        // canary copies and the parent's epilogue traps to
                        // `__stack_chk_fail`.
                        //
                        // Substitute a fresh kernel-allocated 64 KiB VMA in
                        // the shared address space and copy the arg word so
                        // the child's `pop %rdi; call *%r9` preamble still
                        // works.  Recorded on `Thread.vfork_isolated_stack`
                        // for cleanup on execve / vfork-child exit.
                        if new_stack != 0 {
                            match crate::proc::alloc_vfork_child_stack(pid, new_stack) {
                                Some(child_rsp) => {
                                    let mut threads = crate::proc::THREAD_TABLE.lock();
                                    if let Some(t) = threads.iter_mut().find(|t| t.tid == child_tid) {
                                        t.user_entry_rsp = child_rsp;
                                        // Record the isolated-stack VMA so
                                        // we can unmap it later.  Base is
                                        // computed from the RSP we just
                                        // returned; see alloc_vfork_child_stack
                                        // for the size constant.
                                        const VFORK_STACK_SIZE: u64 = 64 * 1024;
                                        // child_rsp = base + length - 8
                                        let base = (child_rsp + 8) - VFORK_STACK_SIZE;
                                        t.vfork_isolated_stack = Some((base, VFORK_STACK_SIZE));
                                    }
                                }
                                None => {
                                    // Fall back to caller-supplied stack with
                                    // a warning — the saga continues if the
                                    // child path is short enough that it
                                    // doesn't overflow.  ENOMEM here would
                                    // otherwise leave us with no place to
                                    // run the child at all.
                                    crate::serial_println!(
                                        "[VFORK] WARN: failed to allocate isolated stack; \
                                         using caller-supplied new_stack={:#x} \
                                         (parent corruption risk)",
                                        new_stack
                                    );
                                    let mut threads = crate::proc::THREAD_TABLE.lock();
                                    if let Some(t) = threads.iter_mut().find(|t| t.tid == child_tid) {
                                        t.user_entry_rsp = new_stack;
                                    }
                                }
                            }
                        }

                        // Per POSIX vfork(2) and clone(2) `CLONE_VM`, the
                        // child shares the parent's address space — including
                        // the parent's TLS region.  Inherit the parent's
                        // FS_BASE so the child's first TLS-relative read
                        // (e.g. `%fs:0x28` SSP-canary load, `%fs:0` TCB
                        // self-pointer in the cancellable-syscall wrapper)
                        // resolves against the parent's TCB, which is mapped
                        // and live throughout the vfork window.  The earlier
                        // `alloc_vfork_child_tls` approach (private TCB page
                        // with zero canary) is no longer used: the SSP
                        // contract requires the value at `%fs:0x28` to match
                        // what the function's prologue pushed, and within a
                        // shared address space that value is the parent's
                        // process-wide canary by construction.  If the
                        // caller supplied `CLONE_SETTLS`, the explicit value
                        // wins.  Refs: AMD64 SysV ABI §3.4.6 (Thread Local
                        // Storage / Variant II); POSIX vfork(2), clone(2);
                        // Intel SDM Vol. 3A §3.4.4.1 (IA32_FS_BASE MSR
                        // 0xC000_0100).
                        let child_tls_base = if flags & CLONE_SETTLS != 0 {
                            tls
                        } else {
                            let threads = crate::proc::THREAD_TABLE.lock();
                            threads.iter().find(|t| t.tid == parent_tid)
                                .map(|t| t.tls_base).unwrap_or(0)
                        };
                        {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == child_tid) {
                                t.tls_base = child_tls_base;
                            }
                        }
                        crate::serial_println!(
                            "[VFORK/TLS] pid={} child_tid={} child_tls_base={:#x} \
                             via={} (inherited from parent_tid={} unless CLONE_SETTLS)",
                            pid, child_tid, child_tls_base,
                            if flags & CLONE_SETTLS != 0 { "CLONE_SETTLS" } else { "parent" },
                            parent_tid,
                        );

                        // CLONE_VFORK prepare-to-wait: register the
                        // child→parent wake mapping BEFORE unblocking the
                        // child.  `wake_vfork_parent()` (called from the
                        // child's execve(2)/exit path) acts only if it
                        // observes `vfork_parent_tid == Some(parent_tid)`,
                        // so the mapping must be visible before the child
                        // can run — otherwise the child reads the initial
                        // `None`, no-ops, and the parent parks with no waker
                        // (lost wakeup, masked today only by the 500-tick
                        // timeout below).  Per POSIX vfork(2): the parent
                        // resumes only after the child execs or exits.
                        if is_vfork {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == child_tid) {
                                t.vfork_parent_tid = Some(parent_tid);
                            }
                        }

                        // Unblock the child so the scheduler can run it.
                        crate::proc::unblock_process(child_pid);

                        // CLONE_VFORK: block parent until child signals completion
                        // (exec/exit) or a timeout expires. Firefox's content process
                        // needs the parent to block so the child can set up IPC first.
                        // Use a 500-tick timeout (~5 seconds) as a safety net.
                        if is_vfork {
                            // Commit Blocked, then recheck the completion
                            // token under the SAME THREAD_TABLE hold.  The
                            // child's `wake_vfork_parent()` clears
                            // `vfork_parent_tid` to `None` when it consumes
                            // the token; if the child already ran (it execed
                            // or exited in the unblock→here window), the
                            // token is already `None` and its Blocked→Ready
                            // flip raced ahead of our `Blocked` commit, so we
                            // must NOT park — revert to Ready and fall
                            // through.  Lock discipline: THREAD_TABLE only,
                            // never nested with PROCESS_TABLE; same lock the
                            // wake side takes, so the recheck is serialized
                            // against the child's clear+flip.
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            let child_completed = threads.iter()
                                .find(|t| t.tid == child_tid)
                                .map(|t| t.vfork_parent_tid.is_none())
                                .unwrap_or(true); // child gone (exited+reaped) ⇒ completed
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == parent_tid) {
                                if child_completed {
                                    // Race detected: wake already happened (or
                                    // child is gone).  Do not park.
                                    t.state = crate::proc::ThreadState::Ready;
                                    t.wake_tick = u64::MAX;
                                } else {
                                    // INVARIANT: Release-store ctx_rsp_valid=false
                                    // BEFORE Blocked (see futex_wait_check_and_enqueue
                                    // in syscall/mod.rs).  The vfork child's completion
                                    // wake can fire from the sibling CPU at any instant
                                    // after this store; the flag is the picker's only
                                    // mid-switch guard against resuming this parent from
                                    // its STALE previous-switch `context.rsp`.
                                    t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
                                    t.state = crate::proc::ThreadState::Blocked;
                                    // Timeout backstop: wake after 500 ticks (~5s)
                                    // even if the child never signals.
                                    let now = crate::arch::x86_64::irq::get_ticks();
                                    t.wake_tick = now.saturating_add(500);
                                }
                            }
                            drop(threads);
                            if child_completed {
                                // Child already completed; skip the park
                                // entirely and return as if resumed.
                                return child_pid as i64;
                            }
                            // VFORK/CANARY pre-block snapshot — see helper.
                            vfork_canary_snapshot("pre_block.clone", pid as u32, parent_tid);
                            // Axis-N+1 three-channel stack-provenance snapshot
                            // + sibling-syscall window + master-canary DR0
                            // watch.  Diagnostic-only; see `vfork_diag.rs`.
                            #[cfg(feature = "vfork-canary-diag")]
                            {
                                crate::subsys::linux::vfork_diag::snapshot_canaries(
                                    "PRE", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_canary_walk(
                                    "PRE", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_finegrain(
                                    "pre", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_page_prov(
                                    "pre", pid, parent_tid);
                                // Axis-O: stash PRE 8 KiB window for the
                                // `#GP`-entry per-qword writer-history
                                // diff.  Tech-lead 2026-05-19 brief.
                                crate::subsys::linux::vfork_diag::store_pre_snapshot(
                                    pid, parent_tid);
                                crate::subsys::linux::vfork_diag::enter_vfork_window(
                                    pid, parent_tid);
                                crate::subsys::linux::vfork_diag::arm_master_canary_watch();
                            }
                            // D21 — arm a write-only DR on the libxul caller-
                            // frame `[rbp-8]` saved-canary slot for PID 1
                            // TID 1.  Catches any writer (kernel or user, any
                            // CR3 that resolves to the watched user VA) to
                            // the SSP slot that the doomed function's
                            // epilogue will compare against `fs:0x28` —
                            // names the user-mode `__stack_chk_fail` writer
                            // post-PR-#400.  Bounded by `D21_ARM_MAX = 4`
                            // and the `F3_FIRE_CAP` per-slot fire bound.
                            // Diagnostic-only; gated behind
                            // `d21-user-canary-watch`.  See PR #398 for the
                            // dispositive evidence trail and PR #399 for
                            // the D20 precedent.
                            #[cfg(feature = "d21-user-canary-watch")]
                            crate::subsys::linux::d21_user_canary_watch::try_arm_at_vfork_preblock(
                                pid, parent_tid);
                            // D22 — PHYS_OFF channel companion to D21 for
                            // phys-aliasing detection (Wave 13).  Arms a
                            // linear watchpoint on the same canary VA AND
                            // a PHYS_OFF mirror on the observed backing
                            // physical frame, so a write that lands on
                            // either side of the user-VA / direct-map
                            // boundary is named.  Per PR #356 K2b two-
                            // channel pattern + PR #407 Wave 12 verdict
                            // (Mechanism D — phys-aliasing on user stack).
                            // Diagnostic-only; gated behind
                            // `d22-user-canary-phys`.
                            #[cfg(feature = "d22-user-canary-phys")]
                            crate::subsys::linux::d22_user_canary_phys::try_arm_at_vfork_preblock(
                                pid, parent_tid);
                            // ELF-WRITE-TRACE on 0x37e18 dropped here — qa
                            // verdict: structurally meaningless on musl
                            // (musl's ld doesn't use a `.data.rel.ro`
                            // function-pointer slot at that offset; only
                            // glibc's `_rtld_global_ro+0x378` does).  TODO:
                            // re-gate to glibc-only when we re-enable the
                            // glibc personality track.
                            crate::sched::schedule();
                            // Resumed: child called exec/exit, or timeout expired.
                            // VFORK/CANARY post-wake snapshot.
                            #[cfg(feature = "vfork-canary-diag")]
                            {
                                crate::subsys::linux::vfork_diag::disarm_master_canary_watch();
                                crate::subsys::linux::vfork_diag::exit_vfork_window();
                                crate::subsys::linux::vfork_diag::snapshot_canaries(
                                    "POST", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_finegrain(
                                    "post", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_page_prov(
                                    "post", pid, parent_tid);
                                // Axis-O: stash POST 8 KiB window and arm
                                // DR write-watchpoints on changed slots so
                                // any post-wake writer is named by the
                                // existing `[W215/DR-WATCH-FIRE]` line in
                                // `arch::x86_64::debug_reg::handle_db_exception`.
                                crate::subsys::linux::vfork_diag::store_post_snapshot(
                                    pid, parent_tid);
                                crate::subsys::linux::vfork_diag::arm_launcher_canary_watches(
                                    pid, parent_tid);
                            }
                            vfork_canary_snapshot("post_wake.clone", pid as u32, parent_tid);
                            // F3 code-DR watch — arm a one-shot
                            // instruction-breakpoint DR on the
                            // deterministic musl `__stack_chk_fail+0x0`
                            // user VA (PR #420 autopsy verdict).  Fires
                            // as a fault before the abort instruction
                            // retires (Intel SDM Vol. 3B §17.3.1.1),
                            // giving a dispositive caller-frame
                            // snapshot for diffing the saved-canary
                            // slot against fs:0x28.  Path-gated to
                            // PID 1 + one-shot per boot.  Diagnostic-
                            // only; gated behind `f3-codeDR-watch`.
                            #[cfg(feature = "f3-codeDR-watch")]
                            crate::subsys::linux::f3_code_dr_watch::try_arm_after_post_wake(
                                pid, parent_tid);
                        }
                        child_pid as i64
                    }
                    None => -11 // EAGAIN
                }
            } else {
                // Fork-style clone: new address space copy.
                // Pass flags and child_tidptr for CLONE_CHILD_SETTID support.
                crate::syscall::sys_fork_impl(flags, arg4)
            }
        }
        // 57: fork
        57 => crate::syscall::sys_fork(),
        // 74: fsync(fd) — flush file data to storage (stub: VFS has no dirty state yet)
        74 => 0,
        // 75: fdatasync(fd) — flush file data (no metadata) to storage (stub)
        75 => 0,
        // 77: ftruncate(fd, length) — truncate open file to given length
        77 => {
            let pid = crate::proc::current_pid_lockless();
            match crate::vfs::fd_truncate(pid, arg1 as usize, arg2) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 82: rename(oldpath, newpath) — C strings
        82 => {
            let old_raw = read_cstring_from_user(arg1);
            let new_raw = read_cstring_from_user(arg2);
            let old_str = core::str::from_utf8(&old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(&new_raw).unwrap_or("");
            match crate::vfs::rename(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 86: link(oldpath, newpath) — create a hard link.  Both are C-string
        // paths.  Implements POSIX `link(2)`; the dominant real-world caller on
        // this path is fontconfig's atomic cache-lock idiom `link(TMP, LCK)`
        // (FcDirCacheLock).  Without it fontconfig cannot lock the cache dir,
        // never persists a font cache, and rescans fonts forever — stalling the
        // content-process font-init thread.
        86 => {
            let old_raw = read_cstring_from_user(arg1);
            let new_raw = read_cstring_from_user(arg2);
            let old_str = core::str::from_utf8(&old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(&new_raw).unwrap_or("");
            match crate::vfs::link(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 89: readlink(path, buf, bufsiz) — C string path
        // Special-cased for /proc/self/exe → returns current process executable path.
        89 => {
            let raw = read_cstring_from_user(arg1);
            let path_str = core::str::from_utf8(&raw).unwrap_or("");
            let buf = arg2 as *mut u8;
            let bufsiz = arg3 as usize;

            // /proc/self/exe — resolve to current process exe path.
            //
            // Per readlink(2), if the target symlink cannot be resolved the
            // syscall returns -ENOENT.  Returning an empty string when
            // `exe_path` is None causes callers that do not check the returned
            // length before slicing (e.g. Mozilla's BinaryPath::Get, which
            // performs `path[0..len-3]`) to panic or fault on an
            // out-of-bounds access.  ENOENT is the correct sentinel: callers
            // such as glibc's `__execvpe` and Mozilla's fallback path handle
            // ENOENT gracefully by switching to an alternative resolution
            // strategy.  (See readlink(2), POSIX.1-2017.)
            let target_str: alloc::string::String = if path_str == "/proc/self/exe"
                || path_str == "/proc/self/fd/exe"
            {
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                match procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.exe_path.as_ref())
                    .map(|s| s.clone())
                {
                    Some(p) => p,
                    None => return -2, // ENOENT — no exe path recorded for this process
                }
            } else if path_str == "/proc/self/cwd"
                || path_str == "/proc/self/root"
            {
                // /proc/self/cwd — readlink returns the process's working
                // directory (per proc(5)).  /proc/self/root — the process's
                // root directory; on AstryxOS this is always "/" because
                // chroot(2) is a stub.  Mozilla / glibc both call readlink
                // here when resolving relative paths — ENOENT/EINVAL caused
                // them to fall back to "/" with a noisy warning.
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                if path_str == "/proc/self/cwd" {
                    procs.iter().find(|p| p.pid == pid)
                        .map(|p| p.cwd.clone())
                        .unwrap_or_else(|| alloc::string::String::from("/"))
                } else {
                    alloc::string::String::from("/")
                }
            } else if path_str.starts_with("/proc/self/fd/") {
                // /proc/self/fd/<N> — returns the open_path for fd N.
                let fd_part = &path_str["/proc/self/fd/".len()..];
                let fd_num = fd_part.parse::<usize>().unwrap_or(usize::MAX);
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.file_descriptors.get(fd_num))
                    .and_then(|f| f.as_ref())
                    .map(|f| f.open_path.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| {
                        alloc::format!("/dev/fd/{}", fd_num)
                    })
            } else {
                // POSIX readlink(2): "If the pathname given in path is
                // relative, it shall be interpreted relative to the calling
                // process's current working directory."  vfs::readlink is
                // CWD-blind, so resolve here.
                let resolved_owned: alloc::string::String = if path_str.starts_with('/')
                    || path_str.is_empty()
                {
                    alloc::string::String::from(path_str)
                } else {
                    const AT_FDCWD: i64 = -100;
                    match resolve_at_path(AT_FDCWD as u64, arg1) {
                        Ok(p) => p,
                        Err(_) => return -22,
                    }
                };
                match crate::vfs::readlink(resolved_owned.as_str()) {
                    Ok(t) => t,
                    Err(_) => return -22, // EINVAL
                }
            };

            let bytes = target_str.as_bytes();
            let len = bytes.len().min(bufsiz);
            if len > 0 {
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len);
                }
            }
            len as i64
        }
        // 157: prctl(option, arg2, arg3, arg4, arg5) — per `man 2 prctl`.
        //
        // Op numbers are stable Linux-UAPI constants from `<sys/prctl.h>` /
        // `<linux/prctl.h>`; see prctl(2) for semantics.
        157 => {
            const PR_SET_PDEATHSIG: u64         = 1;
            const PR_GET_PDEATHSIG: u64         = 2;
            const PR_GET_DUMPABLE: u64          = 3;
            const PR_SET_DUMPABLE: u64          = 4;
            const PR_GET_KEEPCAPS: u64          = 7;
            const PR_SET_KEEPCAPS: u64          = 8;
            const PR_SET_NAME: u64              = 15;
            const PR_GET_NAME: u64              = 16;
            const PR_GET_SECCOMP: u64           = 21;
            const PR_SET_SECCOMP: u64           = 22;
            const PR_CAPBSET_READ: u64          = 23;
            const PR_CAPBSET_DROP: u64          = 24;
            const PR_SET_CHILD_SUBREAPER: u64   = 36;
            const PR_GET_CHILD_SUBREAPER: u64   = 37;
            const PR_SET_NO_NEW_PRIVS: u64      = 38;
            const PR_GET_NO_NEW_PRIVS: u64      = 39;
            const PR_CAP_AMBIENT: u64           = 47;
            // Last capability number defined in Linux uapi/linux/capability.h
            // 5.13 (CAP_CHECKPOINT_RESTORE = 40).  Per `capabilities(7)` and
            // `prctl(2)` PR_CAPBSET_*: arguments outside 0..=CAP_LAST_CAP
            // must return EINVAL.
            const CAP_LAST_CAP: u64             = 40;
            match arg1 {
                PR_SET_NAME => 0,   // ignore thread name
                // PR_GET_NAME(*buf): per prctl(2), "the buffer should allow
                // space for up to 16 bytes; the returned string will be
                // null-terminated."  We range-check the user pointer for the
                // same CWE-822/CWE-823 reason called out on the
                // PR_GET_CHILD_SUBREAPER arm — SMAP AC=1 does not gate
                // kernel-VA writes, so a sandboxed caller passing
                // `arg2 = KERNEL_VIRT_BASE + off` would obtain a 16-byte
                // arbitrary-write primitive.  Write the kernel name padded
                // with NULs to fill the 16-byte buffer that callers
                // (including tokio's worker-thread naming probe) allocate.
                PR_GET_NAME => {
                    if arg2 == 0 { return -14; } // EFAULT
                    if !crate::syscall::user_ptr_check_bypassed()
                        && !crate::syscall::validate_user_ptr(arg2, 16)
                    {
                        return -14; // EFAULT
                    }
                    let mut name = [0u8; 16];
                    let src = b"astryx";
                    name[..src.len()].copy_from_slice(src);
                    // name[6..16] stays zero — NUL terminator + padding
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::copy_nonoverlapping(
                            name.as_ptr(),
                            arg2 as *mut u8,
                            16,
                        );
                    }
                    0
                }
                PR_SET_DUMPABLE          => 0,
                PR_GET_DUMPABLE          => 0,
                // PR_SET_PDEATHSIG(sig): "Set the parent-death signal of the
                // calling process to arg2 (either a signal value in the range
                // 1..maxsig, or 0 to clear)."  Store on the per-process
                // record; delivered by exit_group_inner() when the parent
                // exits.  Cite: prctl(2) "PR_SET_PDEATHSIG (since Linux 2.1.57)".
                PR_SET_PDEATHSIG         => {
                    // Reject out-of-range signal numbers.
                    if arg2 > crate::signal::MAX_SIGNAL as u64 {
                        -22 // EINVAL
                    } else {
                        let pid = crate::proc::current_pid_lockless();
                        let mut procs = crate::proc::PROCESS_TABLE.lock();
                        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                            p.pdeath_signal = arg2 as u8;
                        }
                        0
                    }
                }
                // PR_GET_PDEATHSIG(*intp): write the current pdeath signal into
                // user-space.  We range-check the user pointer for the same
                // reason as PR_GET_CHILD_SUBREAPER (SMAP AC=1 does not gate
                // kernel-VA writes — see CWE-822 commentary on that arm).
                PR_GET_PDEATHSIG         => {
                    if arg2 != 0 {
                        if !crate::syscall::user_ptr_check_bypassed()
                            && !crate::syscall::validate_user_ptr(arg2, 4)
                        {
                            return -14; // EFAULT
                        }
                        let pid = crate::proc::current_pid_lockless();
                        let procs = crate::proc::PROCESS_TABLE.lock();
                        let sig = procs.iter()
                            .find(|p| p.pid == pid)
                            .map(|p| p.pdeath_signal as u32)
                            .unwrap_or(0);
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            core::ptr::write_unaligned(arg2 as *mut u32, sig);
                        }
                    }
                    0
                }
                // PR_CAPBSET_READ(cap): per capabilities(7), return 1 if the
                // capability is in the calling thread's bounding set, 0 if
                // not, -EINVAL if `cap` is invalid.  AstryxOS has no
                // capability model — every process is effectively root —
                // so we report all valid caps as present (1).  This makes
                // the bwrap-style "while CAPBSET_READ(i); CAPBSET_DROP(i)"
                // loop terminate cleanly after dropping all 41 caps.
                PR_CAPBSET_READ          => {
                    if arg2 > CAP_LAST_CAP { -22 } else { 1 }
                }
                // PR_CAPBSET_DROP(cap): per capabilities(7) and prctl(2),
                // remove the capability from the bounding set.  AstryxOS
                // has no capability bounding-set storage, so this is
                // accept-and-return-0; validation matches Linux's
                // input range check.
                //
                // Note: real Linux returns -EPERM if CAP_SETPCAP is not
                // in the effective set, but bwrap and similar tools issue
                // this as root and expect 0 — which we always return.
                PR_CAPBSET_DROP          => {
                    if arg2 > CAP_LAST_CAP { -22 } else { 0 }
                }
                PR_SET_CHILD_SUBREAPER   => 0, // stub: accept but no real subreaper support
                PR_GET_CHILD_SUBREAPER   => {
                    // Report "not a subreaper".  Range-check the user
                    // pointer before the write: SMAP's AC=1 only blocks
                    // CPL-0 access to PTE.U=1 user pages — it does NOT
                    // gate kernel-VA writes (those pages have PTE.U=0
                    // and SMAP is inactive on them), so a sandboxed
                    // process passing `arg2 = KERNEL_VIRT_BASE + offset`
                    // would obtain a 4-byte arbitrary-write primitive
                    // mediated by this stub.  Per prctl(2) ERRORS,
                    // EFAULT is the conformant response for a pointer
                    // outside the caller's address space.
                    //
                    // CWE-822 (Untrusted Pointer Dereference) /
                    // CWE-823 (Use of Out-of-range Pointer Offset).
                    if arg2 != 0 {
                        if !crate::syscall::user_ptr_check_bypassed()
                            && !crate::syscall::validate_user_ptr(arg2, 4)
                        {
                            return -14; // EFAULT
                        }
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            core::ptr::write_unaligned(arg2 as *mut u32, 0);
                        }
                    }
                    0
                }
                PR_SET_NO_NEW_PRIVS      => {
                    if arg2 == 1 {
                        let pid = crate::proc::current_pid_lockless();
                        let mut procs = crate::proc::PROCESS_TABLE.lock();
                        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                            p.no_new_privs = true;
                        }
                    }
                    0
                }
                PR_GET_NO_NEW_PRIVS      => {
                    let pid = crate::proc::current_pid_lockless();
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    procs.iter().find(|p| p.pid == pid)
                        .map(|p| if p.no_new_privs { 1i64 } else { 0i64 })
                        .unwrap_or(0)
                }
                PR_SET_SECCOMP           => 0, // stub: accept any seccomp mode
                PR_GET_SECCOMP           => 0, // SECCOMP_MODE_DISABLED
                PR_SET_KEEPCAPS          => 0,
                PR_GET_KEEPCAPS          => 0,
                PR_CAP_AMBIENT           => 0, // no ambient capability support
                _                        => 0, // permissive default
            }
        }
        // 186: gettid — return current kernel thread ID
        186 => crate::proc::current_tid() as i64,
        // 187: readahead(fd, offset, count) — pre-cache pages; no page cache, return success
        187 => 0,
        // 203: sched_setaffinity(pid, cpusetsize, mask) — stub (accept any)
        203 => 0,
        // 204: sched_getaffinity(pid, cpusetsize, mask) — report all online CPUs.
        // Glibc reads the popcount of this mask to determine nproc; returning
        // only bit 0 would make it report 1 CPU even on SMP systems.
        //
        // Per `man 2 sched_getaffinity` ("C library/kernel differences"):
        //   "On success, the raw sched_getaffinity() system call returns the
        //    number of bytes placed copied into the mask buffer; this will be
        //    the minimum of cpusetsize and the size (in bytes) of the
        //    cpumask_t data type that is used internally by the kernel to
        //    represent the CPU set bit mask."
        //
        // Glibc's `__pthread_getaffinity_np` and Mozilla's mozglue both
        // check `rv > 0` to validate the bitmap; returning 0 here makes them
        // treat the bitmap as invalid and silently fall back to single-CPU
        // assumptions, which under-sizes thread pools.
        //
        // The return value must be `min(cpusetsize, sizeof(cpumask_t))` — NOT
        // the caller's buffer size.  On x86-64 with NR_CPUS <= 64 the kernel's
        // internal cpumask_t is one unsigned long = 8 bytes; real Linux returns
        // 8 here (verified against a golden strace), and consumers that inspect
        // the byte count (rather than just popcounting) rely on that exact
        // value.  We support MAX_CPUS=16, which fits in 8 bytes.  The libc
        // wrapper zeroes any remaining bytes of a larger caller buffer.
        204 => {
            let buf = arg3 as *mut u8;
            let bufsiz = arg2 as usize;
            const KERNEL_CPUMASK_BYTES: usize = 8;
            let written = bufsiz.min(KERNEL_CPUMASK_BYTES);
            if buf == core::ptr::null_mut() || written == 0 {
                // Nothing to write — preserve permissive 0 return for NULL/zero
                // (real Linux returns -EFAULT here; glibc never invokes this path).
                0
            } else {
                let ncpus = crate::arch::x86_64::apic::cpu_count() as usize;
                let ncpus = ncpus.max(1); // always at least 1
                // Zero the buffer, then set one bit per online CPU.
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::write_bytes(buf, 0, written);
                    // Set bits 0..ncpus-1 in the cpuset bitmask (little-endian).
                    // Each byte covers 8 CPUs.  We support up to written*8 CPUs.
                    for cpu in 0..ncpus {
                        let byte_idx = cpu / 8;
                        let bit_idx  = cpu % 8;
                        if byte_idx < written {
                            let byte_ptr = buf.add(byte_idx);
                            *byte_ptr |= 1u8 << bit_idx;
                        }
                    }
                }
                // Return bytes-copied: min(cpusetsize, sizeof(cpumask_t)).
                written as i64
            }
        }
        // 209: io_setup stub
        209 => -38,
        // 213: epoll_create(size) — same semantics as epoll_create1(0)
        213 => sys_epoll_create1(0),
        // 232: epoll_wait(epfd, events_ptr, maxevents, timeout_ms)
        232 => sys_epoll_wait(arg1 as usize, arg2, arg3 as usize, arg4 as i32),
        // 233: epoll_ctl(epfd, op, fd, event_ptr)
        233 => sys_epoll_ctl(arg1 as usize, arg2, arg3 as usize, arg4),
        // 273: set_robust_list(head, len)
        // Store head pointer + length in the calling thread for later retrieval.
        // The kernel only uses this during thread death (to mark locked mutexes as
        // abandoned), which we don't implement, but we must store it so that
        // get_robust_list returns the same values (glibc consistency check).
        273 => {
            let head = arg1;
            let len  = arg2 as usize;
            let tid  = crate::proc::current_tid();
            let mut threads = crate::proc::THREAD_TABLE.lock();
            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                t.robust_list_head = head;
                t.robust_list_len  = len;
            }
            0
        }
        // 274: get_robust_list(pid, head_ptr_ptr, len_ptr)
        // Return the robust-list head pointer and length stored by set_robust_list.
        // pid == 0 means the calling thread; non-zero means another thread by TID.
        274 => {
            let target_tid = if arg1 == 0 {
                crate::proc::current_tid()
            } else {
                arg1
            };
            let threads = crate::proc::THREAD_TABLE.lock();
            if let Some(t) = threads.iter().find(|t| t.tid == target_tid) {
                let head = t.robust_list_head;
                let len  = t.robust_list_len;
                drop(threads);
                // Write head pointer into *head_ptr (arg2 is **robust_list_head)
                // and length into *len_ptr — both user pointers.  Each
                // is range-checked before the write so a sandboxed
                // process cannot supply `arg2 = KERNEL_VIRT_BASE + off`
                // to obtain an 8-byte arbitrary-write primitive (SMAP
                // only blocks CPL-0 writes to PTE.U=1 user pages;
                // kernel-VA pages are PTE.U=0 and SMAP is inactive on
                // them).  Per get_robust_list(2) ERRORS, EFAULT is the
                // conformant response for an inaccessible pointer.
                //
                // CWE-822 / CWE-823.  Same threat class as the audit's
                // C2 finding (iovec kernel-VA, closed in PR #242).
                if arg2 != 0
                    && !crate::syscall::user_ptr_check_bypassed()
                    && !crate::syscall::validate_user_ptr(arg2, 8)
                {
                    return -14; // EFAULT
                }
                if arg3 != 0
                    && !crate::syscall::user_ptr_check_bypassed()
                    && !crate::syscall::validate_user_ptr(arg3, 8)
                {
                    return -14; // EFAULT
                }
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    if arg2 != 0 { core::ptr::write(arg2 as *mut u64, head); }
                    if arg3 != 0 { core::ptr::write(arg3 as *mut usize, len); }
                }
                0
            } else {
                drop(threads);
                -3 // ESRCH — no such thread
            }
        }
        // 281: epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize)
        //      Same as epoll_wait but with optional signal mask — we ignore the mask.
        281 => sys_epoll_wait(arg1 as usize, arg2, arg3 as usize, arg4 as i32),
        // 291: epoll_create1(flags)
        291 => sys_epoll_create1(arg1 as u32),
        // 309: getcpu(cpu, node, cache) — stub.  Both `cpu` and `node`
        // are user pointers that we range-check before writing; the
        // third arg (`cache`) is deprecated and ignored per getcpu(2)
        // NOTES (it has had no effect since Linux 2.6.24).
        //
        // Without the range check, a sandboxed process passing
        // `arg1 = KERNEL_VIRT_BASE + off` obtains a 4-byte
        // arbitrary-write primitive of the value 0 — SMAP's AC=1 only
        // blocks CPL-0 writes to PTE.U=1 user pages and is inactive on
        // kernel-VA pages (PTE.U=0).  Even a constant-zero write is a
        // weaponisable primitive (clear an `enabled` flag, NULL a
        // function pointer, blank an audit-record field).  CWE-822 /
        // CWE-823; same threat class as the audit's C2 finding.
        //
        // Per getcpu(2) ERRORS, EFAULT is the conformant response.
        309 => {
            if arg1 != 0
                && !crate::syscall::user_ptr_check_bypassed()
                && !crate::syscall::validate_user_ptr(arg1, 4)
            {
                return -14; // EFAULT
            }
            if arg2 != 0
                && !crate::syscall::user_ptr_check_bypassed()
                && !crate::syscall::validate_user_ptr(arg2, 4)
            {
                return -14; // EFAULT
            }
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                if arg1 != 0 { core::ptr::write(arg1 as *mut u32, 0); }
                if arg2 != 0 { core::ptr::write(arg2 as *mut u32, 0); }
            }
            0
        }
        // 59: execve(pathname, argv, envp) — pathname is C string
        59 => {
            let path_bytes = read_cstring_from_user(arg1);
            crate::syscall::sys_exec(arg1, path_bytes.len() as u64, arg2, arg3)
        }
        // 60: exit(status)
        // exit_thread() loops on schedule() until this thread is switched
        // away permanently; it never returns.  The trailing `0` satisfies
        // the type-checker (dispatch_body returns i64) but is dead code —
        // POSIX exit(2): "The exit() function shall not return."
        60 => {
            crate::proc::exit_thread(arg1 as i64);
            0 // dead — exit_thread diverges
        }
        // 61: wait4(pid, wstatus, options, rusage)
        //
        // Returns the reaped child pid AND, when `wstatus` (arg2) is non-NULL,
        // writes the encoded wait status so the caller's `WIFEXITED` /
        // `WEXITSTATUS` / `WIFSIGNALED` / `WTERMSIG` macros decode correctly
        // (Linux man-pages `wait(2)`, "status").  Without this, a `waitpid()`
        // wrapper (musl/glibc `waitpid` → `wait4`) reads an uninitialised
        // status and mis-classifies the child's exit.  Encoding:
        //   normal exit:  (exit_status & 0xff) << 8
        //   killed:       signo (low 7 bits); AstryxOS stores `-signo`.
        61 => {
            let want = arg1 as i64;
            let mut exit_code: i32 = 0;
            let ret = crate::syscall::sys_waitpid_ex(
                want, (arg3 & 1) != 0 /*WNOHANG*/, false /*WNOWAIT*/,
                Some(&mut exit_code));
            if ret > 0 && arg2 != 0
                && (crate::syscall::user_ptr_check_bypassed()
                    || crate::syscall::validate_user_ptr(arg2, 4))
            {
                let wstatus: i32 = if exit_code < 0 {
                    (-exit_code) & 0x7f                  // WIFSIGNALED: WTERMSIG
                } else {
                    (exit_code & 0xff) << 8              // WIFEXITED:  WEXITSTATUS
                };
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::write_unaligned(arg2 as *mut i32, wstatus);
                }
            }
            ret
        }
        // 62: kill(pid, sig)
        62 => crate::signal::kill(arg1, arg2 as u8),
        // 72: fcntl(fd, cmd, arg)
        72 => sys_fcntl(arg1, arg2, arg3),
        // 79: getcwd(buf, size) — user-mode entry gate on buf (CWE-823).
        79 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && arg2 != 0
                && !crate::syscall::validate_user_ptr(arg1, arg2 as usize)
            {
                return -14;
            }
            crate::syscall::sys_getcwd(arg1 as *mut u8, arg2 as usize)
        }
        // 80: chdir(pathname) — C string
        80 => sys_chdir_linux(arg1),
        // 81: fchdir(fd) — change CWD to the directory opened as fd
        81 => sys_fchdir_linux(arg1),
        // 83: mkdir(pathname, mode) — C string
        83 => sys_mkdir_linux(arg1, arg2),
        // 84: rmdir(pathname) — C string
        84 => sys_rmdir_linux(arg1),
        // 87: unlink(pathname) — C string
        87 => sys_unlink_linux(arg1),
        // 88: symlink(oldpath, newpath) — POSIX symlink(2): the contents
        // of the symlink (oldpath/target) are stored verbatim and MAY be
        // relative (resolved at lookup time, not creation).  newpath is
        // the location where the symlink is created and follows normal
        // pathname resolution (relative paths anchored at CWD).
        88 => {
            let old_raw = read_cstring_from_user(arg1);
            let old_str = core::str::from_utf8(&old_raw).unwrap_or("");
            let new_bytes = match resolve_user_path_to_owned(arg2) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let new_len = new_bytes.iter().position(|&b| b == 0).unwrap_or(new_bytes.len());
            let new_str = match core::str::from_utf8(&new_bytes[..new_len]) {
                Ok(s) => s,
                Err(_) => return -22,
            };
            match crate::vfs::symlink(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => -(e as usize as i64),
            }
        }
        // 96: gettimeofday(tv, tz) — user-mode entry gate on tv (CWE-823).
        // Null tv is a valid no-op (handler returns 0 without writing).
        96 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && arg1 != 0
                && !crate::syscall::validate_user_ptr(arg1, 16)
            {
                return -14;
            }
            sys_gettimeofday(arg1, arg2)
        }
        // 102: getuid
        102 => crate::syscall::sys_getuid(),
        // 104: getgid
        104 => crate::syscall::sys_getgid(),
        // 107: geteuid
        107 => crate::syscall::sys_geteuid(),
        // 108: getegid
        108 => crate::syscall::sys_getegid(),
        // 110: getppid
        110 => crate::syscall::sys_getppid(),
        // 131: sigaltstack(ss, old_ss) — stub
        131 => 0,
        // 158: arch_prctl(code, addr) — user-mode entry gate on addr for
        // ARCH_GET_FS/ARCH_GET_GS only.  For ARCH_SET_FS/ARCH_SET_GS, the
        // `addr` arg is the MSR value to write (not a pointer), so no
        // range check applies.  CWE-823.  Stricter low-canonical bound
        // rejects the non-canonical hole — a non-canonical write would
        // #GP rather than #PF and panic the kernel.
        158 => {
            const ARCH_GET_FS: u64 = 0x1003;
            const ARCH_GET_GS: u64 = 0x1004;
            const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;
            if !crate::syscall::user_ptr_check_bypassed()
                && (arg1 == ARCH_GET_FS || arg1 == ARCH_GET_GS)
                && (arg2 >= USER_PTR_MAX
                    || !crate::syscall::validate_user_ptr(arg2, 8))
            {
                return -14;
            }
            sys_arch_prctl(arg1, arg2)
        }
        // 125: capget(_capuser_header_t hdrp, capuser_data_t datap)
        125 => {
            // Return all capabilities (root-equivalent) for the calling process.
            // struct __user_cap_data_struct: effective(u32), permitted(u32), inheritable(u32)
            // For version 3 (0x20080522), two consecutive structs are expected (64-bit caps).
            if arg2 != 0 && crate::syscall::validate_user_ptr(arg2, 24) {
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                let (eff, perm) = procs.iter().find(|p| p.pid == pid)
                    .map(|p| (p.cap_effective as u32, p.cap_permitted as u32))
                    .unwrap_or((!0u32, !0u32));
                drop(procs);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    let p = arg2 as *mut u32;
                    // struct 0: effective, permitted, inheritable
                    core::ptr::write_unaligned(p,         eff);
                    core::ptr::write_unaligned(p.add(1),  perm);
                    core::ptr::write_unaligned(p.add(2),  0u32); // inheritable
                    // struct 1: upper 32 bits (always 0 for us)
                    core::ptr::write_unaligned(p.add(3),  0u32);
                    core::ptr::write_unaligned(p.add(4),  0u32);
                    core::ptr::write_unaligned(p.add(5),  0u32);
                }
            }
            0
        }
        // 126: capset(_capuser_header_t hdrp, const capuser_data_t datap)
        126 => {
            // Accept capability drops; update effective/permitted in PCB.
            if arg2 != 0 && crate::syscall::validate_user_ptr(arg2, 12) {
                let pid = crate::proc::current_pid_lockless();
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    let dp = arg2 as *const u32;
                    let (eff, perm) = unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        (core::ptr::read_unaligned(dp),
                         core::ptr::read_unaligned(dp.add(1)))
                    };
                    p.cap_effective  = eff  as u64;
                    p.cap_permitted  = perm as u64;
                }
            }
            0
        }
        // 160: setrlimit(resource, rlim) — update per-process soft limit
        160 => {
            let resource = arg1 as usize;
            if resource >= 16 { return -22; } // EINVAL
            if !crate::syscall::validate_user_ptr(arg2, 16) { return -14; } // EFAULT
            let soft = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::read_unaligned(arg2 as *const u64)
            };
            let pid = crate::proc::current_pid_lockless();
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.rlimits_soft[resource] = soft;
            }
            0
        }
        // 202: futex(uaddr, futex_op, val, timeout, uaddr2, val3)
        // arg6 carries `val3` (the bitset for FUTEX_WAIT_BITSET / FUTEX_WAKE_BITSET,
        // and val3 for FUTEX_CMP_REQUEUE).  See futex(2).
        202 => sys_futex_linux(arg1, arg2, arg3, arg4, arg5, arg6),
        // 217: getdents64(fd, dirp, count)
        217 => sys_getdents64(arg1, arg2, arg3),
        // 218: set_tid_address(tidptr) — user-mode entry gate (CWE-823,
        // deferred-liability variant: validate at store time so the
        // exit-time CLEAR_TID write through the process page tables can
        // never resolve to a kernel/non-canonical address).  Per
        // set_tid_address(2) the syscall "always succeeds"; on
        // validation failure we decline the side effect and still
        // return TID — observationally indistinguishable from a thread
        // that never registered a CLEAR_TID slot.
        218 => {
            const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;
            // Decline side effect on any bad ptr (kernel-VA, non-canonical
            // hole, or wrap-around).  Still return TID per the ABI.
            // In-kernel test callers (via dispatch_linux_kernel) bypass.
            if !crate::syscall::user_ptr_check_bypassed()
                && arg1 != 0
                && (arg1 >= USER_PTR_MAX
                    || !crate::syscall::validate_user_ptr(arg1, 4))
            {
                return crate::proc::current_tid() as i64;
            }
            sys_set_tid_address(arg1)
        }
        // 228: clock_gettime(clockid, tp) — user-mode entry gate on tp
        // (CWE-823).  Null tp is rejected by the handler (EINVAL).
        228 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && arg2 != 0
                && !crate::syscall::validate_user_ptr(arg2, 16)
            {
                return -14;
            }
            sys_clock_gettime(arg1, arg2)
        }
        // 231: exit_group(status) — terminate all threads in the process
        // exit_group() marks all sibling threads Dead, frees process memory,
        // and loops on schedule() until this thread is switched away; it
        // never returns.  The trailing `0` is dead code — POSIX exit(2):
        // "The exit() function shall not return."
        231 => {
            crate::serial_println!("[SYSCALL/Linux] exit_group({})", arg1 as i32);
            crate::proc::exit_group(arg1 as i64);
            0 // dead — exit_group diverges
        }
        // 234: tgkill(tgid, tid, sig)
        // Sends signal `sig` to thread `tid` in thread group `tgid`.
        // For single-threaded processes tgid == pid; look up by tgid (arg1),
        // not by tid (arg2) which is only a thread identifier, not a process id.
        234 => crate::signal::kill(arg1, arg3 as u8),
        // 247: waitid(idtype, id, infop, options, rusage)
        // idtype: P_ALL=0, P_PID=1, P_PGID=2
        // options: WEXITED=4, WNOHANG=1, WSTOPPED=2, WCONTINUED=8
        247 => {
            let idtype  = arg1 as u32;
            let id      = arg2 as i64;
            let infop   = arg3 as *mut u8; // siginfo_t*
            let options = arg4 as u32;
            // POSIX `waitid(2)` option bits (Linux UAPI <linux/wait.h>):
            const WNOHANG:  u32 = 0x0000_0001;
            const WEXITED:  u32 = 0x0000_0004;
            const WNOWAIT:  u32 = 0x0100_0000;
            let pid: i64 = match idtype {
                0 => -1,    // P_ALL  — any child
                1 => id,    // P_PID  — specific pid
                2 => -id,   // P_PGID — process group (approximate as -pgid)
                _ => return -22, // EINVAL
            };
            if options & WEXITED == 0 { return -22; } // must request at least WEXITED
            // Honour WNOWAIT: peek the child's status but leave it in a
            // waitable state, so the canonical "waitid(WNOWAIT) then
            // waitid(reap)" idiom (used by process launchers to observe a
            // child's exit before collecting it) does not race-reap the child
            // on the first call and hang the second against an already-gone pid.
            match crate::syscall::sys_waitid(
                pid, options & WNOHANG != 0, options & WNOWAIT != 0)
            {
                crate::syscall::WaitidOutcome::Collected { pid: child, si_code, si_status } => {
                    // Serialise the user `siginfo_t` for SIGCHLD per
                    // POSIX.1-2017 `waitid(2)` and Linux
                    // `<asm-generic/siginfo.h>`.  The x86-64 (LP64) field
                    // offsets live in `crate::syscall` (si_pid @16, si_status
                    // @24 — the `_sifields` union is 8-byte aligned and starts
                    // at offset 16, NOT 12).  Writing si_pid at the wrong
                    // offset makes a reader that branches on `si_pid` (gecko's
                    // IsProcessDead: `if (si.si_pid == 0) return Running;`) see a
                    // zero pid and busy-loop the blocking `waitid(WNOWAIT)`
                    // forever, pinning the caller's thread.
                    if !infop.is_null()
                        && (crate::syscall::user_ptr_check_bypassed()
                            || crate::syscall::validate_user_ptr(
                                arg3, crate::syscall::SI_SIZE))
                    {
                        let uid = {
                            let cur = crate::proc::current_pid_lockless();
                            crate::proc::PROCESS_TABLE.lock()
                                .iter().find(|p| p.pid == cur)
                                .map(|p| p.uid as i32).unwrap_or(0)
                        };
                        let mut si = [0u8; crate::syscall::SI_SIZE];
                        crate::syscall::fill_sigchld_siginfo(
                            &mut si, si_code, child as i32, uid, si_status);
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            core::ptr::copy_nonoverlapping(
                                si.as_ptr(), infop, crate::syscall::SI_SIZE);
                        }
                    }
                    0 // waitid returns 0 on success (not child pid)
                }
                // WNOHANG, nothing ready: per `waitid(2)`, return 0 with a
                // zeroed `si_pid` so the caller sees "no child changed state".
                crate::syscall::WaitidOutcome::NoHang => {
                    if !infop.is_null()
                        && (crate::syscall::user_ptr_check_bypassed()
                            || crate::syscall::validate_user_ptr(
                                arg3, crate::syscall::SI_SIZE))
                    {
                        unsafe {
                            let _g = crate::arch::x86_64::smap::UserGuard::new();
                            core::ptr::write_bytes(infop, 0, crate::syscall::SI_SIZE);
                        }
                    }
                    0
                }
                crate::syscall::WaitidOutcome::Err(e) => e, // negative errno
            }
        }
        // 257: openat(dirfd, pathname, flags, mode)
        257 => {
            // openat — user-mode entry gate on pathname (CWE-823).
            // Internal kernel callers wrap via dispatch_linux_kernel.
            if !crate::syscall::user_ptr_check_bypassed()
                && !user_path_ptr_ok(arg2) { return -14; }
            sys_openat(arg1, arg2, arg3, arg4)
        }
        // 262: newfstatat(dirfd, pathname, statbuf, flags)
        262 => sys_newfstatat(arg1, arg2, arg3, arg4),
        // 302: prlimit64(pid, resource, new_limit, old_limit)
        302 => {
            // GET old limit if requested
            if arg4 != 0 {
                let r = sys_getrlimit(arg2, arg4);
                if r < 0 { return r; }
            }
            // SET new limit if provided
            if arg3 != 0 && (arg2 as usize) < 16 && crate::syscall::validate_user_ptr(arg3, 16) {
                let soft = unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::read_unaligned(arg3 as *const u64)
                };
                let pid  = crate::proc::current_pid_lockless();
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    p.rlimits_soft[arg2 as usize] = soft;
                }
            }
            0
        }
        // 318: getrandom(buf, buflen, flags)
        318 => crate::syscall::sys_getrandom(arg1 as *mut u8, arg2 as usize, arg3 as u32),
        // 324: membarrier(cmd, flags, cpu_id) — per `man 2 membarrier` (Linux 4.3+).
        //
        // Command set per `<linux/membarrier.h>` (kernel UAPI):
        //   MEMBARRIER_CMD_QUERY                                  = 0
        //   MEMBARRIER_CMD_GLOBAL                                 = (1<<0) = 0x01
        //   MEMBARRIER_CMD_GLOBAL_EXPEDITED                       = (1<<1) = 0x02
        //   MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED              = (1<<2) = 0x04
        //   MEMBARRIER_CMD_PRIVATE_EXPEDITED                      = (1<<3) = 0x08
        //   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED             = (1<<4) = 0x10
        //   MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE            = (1<<5) = 0x20
        //   MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE   = (1<<6) = 0x40
        //
        // musl-FF observed at sc=39 issuing cmd=0x10 (REGISTER_PRIVATE_EXPEDITED)
        // once per process; returning EINVAL previously caused content-process
        // bringup to take the synchronous-barrier fallback path.
        //
        // AstryxOS issues a global mfence+lfence on every barrier command —
        // conservative but correct: on x86_64 stores are TSO-ordered, so the
        // resulting barrier exceeds the membarrier(2) spec ("ordering of memory
        // accesses by user-space threads") in both required directions.  The
        // REGISTER_* arms are accept-and-return-0: they exist so the kernel can
        // pre-allocate per-task state, which AstryxOS does not need.
        324 => {
            // Bits per command index, matching the cmd numeric value when
            // used as an OR-able bitmask.  We advertise everything we accept.
            const MEMBARRIER_SUPPORTED: i64 =
                0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40;
            match arg1 as i64 {
                0 => MEMBARRIER_SUPPORTED,
                // Barrier-issuing commands — emit a real fence.
                0x01 | 0x02 | 0x08 | 0x20 => {
                    unsafe { core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags)); }
                    0
                }
                // Registration commands — accept as a no-op; AstryxOS does not
                // require per-task opt-in for any barrier variant.
                0x04 | 0x10 | 0x40 => 0,
                _ => -22, // EINVAL — unknown command
            }
        }
        // 334: rseq(rseq_ptr, rseq_len, flags, sig) — restartable sequences.
        //
        // The rseq syscall registers a per-thread shared memory area that the
        // kernel updates on preemption/migration so that user-space can restart
        // in-flight per-CPU operations without a syscall.  We do not implement
        // the rseq ABI; returning 0 (success) tells glibc 2.34 that rseq is
        // available.  glibc's fast paths use the rseq region only as an
        // optimisation; when the kernel never writes to the region, glibc falls
        // back to its non-rseq atomic primitives transparently.
        //
        // Returning ENOSYS (-38) caused glibc 2.34 __rseq_init() to treat the
        // thread as broken and abort browser content-process initialisation
        // before any rendering work could begin (W210 investigation).
        //
        // Reference: https://man7.org/linux/man-pages/man2/rseq.2.html
        334 => 0, // success — rseq accepted but not implemented

        // ─── Phase 6 additions ────────────────────────────────────────────

        // 137: statfs(path, buf) — filesystem statistics
        137 => sys_statfs_linux(arg1, arg2 as *mut u8),
        // 138: fstatfs(fd, buf) — filesystem statistics (fd-based)
        138 => sys_fstatfs_linux(arg1 as usize, arg2 as *mut u8),
        // 266: symlinkat(oldpath, newdirfd, newpath)
        266 => {
            let old_raw = read_cstring_from_user(arg1);
            let new_raw = read_cstring_from_user(arg3);
            let old_str = core::str::from_utf8(&old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(&new_raw).unwrap_or("");
            match crate::vfs::symlink(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => -(e as usize as i64),
            }
        }
        // 269: faccessat(dirfd, pathname, mode, flags) — access + dirfd
        269 => sys_faccessat_linux(arg1, arg2, arg3),
        // 280: utimensat(dirfd, pathname, times, flags) — stub success
        280 => 0,
        // 284: eventfd(initval) — legacy form, no flags argument
        284 => sys_eventfd_linux(arg1 as u64, 0),
        // 290: eventfd2(initval, flags) — takes EFD_NONBLOCK / EFD_CLOEXEC / EFD_SEMAPHORE
        290 => sys_eventfd_linux(arg1 as u64, arg2 as u32),
        // 293: pipe2(pipefd, flags) — like pipe but with O_CLOEXEC/O_NONBLOCK
        293 => sys_pipe2_linux(arg1 as *mut u32, arg2 as u32),
        // 435: clone3(clone_args *args, size_t size)
        // clone_args layout (offsets in bytes):
        //   0:  flags(u64), 8: pidfd(u64), 16: child_tid(u64), 24: parent_tid(u64),
        //   32: exit_signal(u64), 40: stack(u64), 48: stack_size(u64), 56: tls(u64)
        //
        // glibc 2.34+ __clone3_wrapper passes thread fn in rdx (arg3) and thread arg
        // in r8 (arg5) through the syscall; the child does:  mov rdi, r8; call *rdx.
        // We must preserve these into the new thread's registers via user_entry_rdx/r8.
        435 => {
            // CLONE_ARGS_SIZE_VER0 = 64 bytes (covers flags..tls).  Anything
            // smaller cannot supply a tls offset; reject per clone(2).
            if arg2 < 64 || arg1 == 0 { return -22i64; } // EINVAL: struct too small
            // SMAP bracket the struct clone_args reads.
            let (clone_flags, stack_ptr, stack_size, tls, child_tidptr, parent_tidptr) = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                (*(arg1 as *const u64),
                 *((arg1 + 40) as *const u64),
                 *((arg1 + 48) as *const u64),
                 *((arg1 + 56) as *const u64),
                 *((arg1 + 16) as *const u64),
                 *((arg1 + 24) as *const u64))
            };
            #[cfg(feature = "firefox-test-core")]
            crate::serial_println!(
                "[CLONE3] flags={:#x} child_tid={:#x} parent_tid={:#x} arg2_size={}",
                clone_flags, child_tidptr, parent_tidptr, arg2
            );
            let sp = if stack_ptr != 0 { stack_ptr + stack_size } else { 0 };
            const CLONE_THREAD: u64 = 0x00010000;
            const CLONE_VM:     u64 = 0x00000100;
            const CLONE_SETTLS: u64 = 0x00080000;
            if clone_flags & CLONE_THREAD != 0 && clone_flags & CLONE_VM != 0 {
                // pthread_create via clone3: glibc passes func in rdx (arg3), arg in r8 (arg5).
                let func       = arg3; // Linux rdx = thread function
                let thread_arg = arg5; // Linux r8  = thread argument (glibc's saved rcx)
                let user_rip   = unsafe { crate::syscall::get_user_rip() };
                let tls_val    = if clone_flags & CLONE_SETTLS != 0 { tls } else { 0 };
                let pid        = crate::proc::current_pid_lockless();
                crate::serial_println!(
                    "[CLONE3] CLONE_THREAD pid={} rip={:#x} sp={:#x} tls={:#x} func={:#x} arg={:#x}",
                    pid, user_rip, sp, tls_val, func, thread_arg
                );
                match crate::proc::usermode::create_user_thread(pid, user_rip, sp, tls_val, func, thread_arg) {
                    Some(tid) => {
                        crate::serial_println!("[CLONE3] Thread TID {} spawned in PID {}", tid, pid);
                        // CLONE-ARGS-DIAG: clone3 passes func/arg in registers
                        // (RDX/R8 per glibc 2.34+ __clone3_wrapper convention;
                        // see syscall.rs::dispatch::435 docstring).  No args
                        // struct to dereference — record the inline values
                        // directly with args_va=0 as the "in-register form"
                        // marker.  Per POSIX pthread_create(3), clone3(2),
                        // AMD64 SysV ABI §3.4.
                        #[cfg(feature = "clone-args-diag")]
                        crate::subsys::linux::clone_args_diag::record_clone_args(
                            pid as u32, tid as u32, clone_flags, 0, func, thread_arg,
                        );

                        // CLONE_CHILD_SETTID: write the child TID into the child's TLS/TCB.
                        // glibc's pthread_create sets this so that the TCB's `tid` field is
                        // populated — required for pthread_rwlock, pthread_mutex, etc. which
                        // read THREAD_GETMEM(THREAD_SELF, tid).  Without this, the tid field
                        // is 0 and glibc's rwlock returns EDEADLK (0 == __cur_writer's 0).
                        const CLONE_CHILD_SETTID: u64 = 0x01000000;
                        if clone_flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 {
                            unsafe { crate::syscall::write_u32_to_user_current(child_tidptr, tid as u32); }
                        }

                        // CLONE_PARENT_SETTID: write child TID into parent's address space.
                        const CLONE_PARENT_SETTID: u64 = 0x00100000;
                        if clone_flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
                            unsafe { crate::syscall::write_u32_to_user_current(parent_tidptr, tid as u32); }
                        }

                        // CLONE_CHILD_CLEARTID: store address for futex wake on thread exit.
                        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
                        if clone_flags & CLONE_CHILD_CLEARTID != 0 && child_tidptr != 0 {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == tid as u64) {
                                t.clear_child_tid = child_tidptr;
                            }
                        }

                        tid as i64
                    }
                    None => -11, // EAGAIN
                }
            } else if clone_flags & CLONE_VM != 0 {
                // CLONE_VM without CLONE_THREAD via clone3 = vfork-/posix_spawn-style.
                // The child SHARES the parent's page tables — writes by the child
                // to parent-visible addresses (e.g. glibc's `args.err = errno`)
                // must be observable to the parent.  See clone3(2) and the
                // posix_spawn(3) fast-path "spawnix" implementation contract.
                //
                // glibc's __clone3 passes func in RDX and arg in R8/RCX.
                // The child path does: mov rdi, r8; call *rdx.
                // We must set entry_rdx/entry_r8 BEFORE unblocking the child.
                let func = arg3; // RDX at clone3 = func pointer
                let thread_arg = arg5; // R8 at clone3 = arg pointer (via RCX→R8)
                let original_rip = unsafe { crate::syscall::get_user_rip() };
                let pid = crate::proc::current_pid_lockless();
                let parent_tid = crate::proc::current_tid();
                let parent_regs = crate::syscall::read_fork_user_regs();

                // CLONE_CLEAR_SIGHAND lives in the upper half of clone_args.flags
                // (bit 32) per clone3(2).  It cannot be combined with CLONE_SIGHAND.
                let is_vfork = clone_flags & CLONE_VFORK != 0;

                // Reject the explicitly-illegal combination per clone3(2).
                if clone_flags & CLONE_CLEAR_SIGHAND != 0
                    && clone_flags & CLONE_SIGHAND != 0
                {
                    return -22; // EINVAL
                }

                crate::serial_println!("[CLONE3-VM] pid={} func={:#x} arg={:#x} rip={:#x} sp={:#x} clear_sighand={}",
                    pid, func, thread_arg, original_rip, sp,
                    clone_flags & CLONE_CLEAR_SIGHAND != 0);

                match crate::proc::fork_process_share_vm(pid, parent_tid, &parent_regs) {
                    Some((child_pid, child_tid)) => {
                        // CLONE_CLEAR_SIGHAND: reset child's sigactions (SIG_IGN
                        // preserved, everything else → SIG_DFL).  Done AFTER
                        // fork_process_share_vm so the child has its own fresh
                        // SignalState to mutate.  Per clone3(2).
                        if clone_flags & CLONE_CLEAR_SIGHAND != 0 {
                            crate::proc::clear_sighand(child_pid);
                        }

                        // Inherit parent's FS_BASE for the vfork child (or
                        // honour CLONE_SETTLS when supplied).  Mirrors the
                        // legacy clone(56) path's TLS-inheritance block: per
                        // POSIX vfork(2)/clone(2) `CLONE_VM` the child shares
                        // the parent's address space, so the parent's TLS
                        // region is the correct backing for the child's
                        // `%fs:0`-relative reads (TCB self-pointer, SSP
                        // canary at `%fs:0x28`, cancellable-syscall state).
                        // Refs: AMD64 SysV ABI §3.4.6; POSIX vfork(2),
                        // clone(2), clone3(2); Intel SDM Vol. 3A §3.4.4.1
                        // (IA32_FS_BASE MSR 0xC000_0100).
                        let child_tls_base = if clone_flags & CLONE_SETTLS != 0 {
                            tls
                        } else {
                            let threads = crate::proc::THREAD_TABLE.lock();
                            threads.iter().find(|t| t.tid == parent_tid)
                                .map(|t| t.tls_base).unwrap_or(0)
                        };

                        // Set func/arg and original RIP BEFORE unblocking
                        {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == child_tid) {
                                t.user_entry_rdx = func;
                                t.user_entry_r8 = thread_arg;
                                t.user_entry_rip = original_rip; // clone3 child uses call *rdx
                                if sp != 0 {
                                    t.user_entry_rsp = sp; // use the new_stack from clone3
                                }
                                t.tls_base = child_tls_base;
                            }
                        }
                        crate::serial_println!(
                            "[CLONE3-VM] child PID {} TID {} rdx={:#x} r8={:#x} rip={:#x} rsp={:#x} tls_base={:#x} via={}",
                            child_pid, child_tid, func, thread_arg, original_rip, sp,
                            child_tls_base,
                            if clone_flags & CLONE_SETTLS != 0 { "CLONE_SETTLS" } else { "parent" });

                        // CLONE_VFORK prepare-to-wait: register the
                        // child→parent wake mapping BEFORE unblocking the
                        // child, for the same lost-wakeup reason documented
                        // at the clone(56) site above (wake_vfork_parent acts
                        // only on `Some(parent_tid)`).  Per POSIX vfork(2).
                        if is_vfork {
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == child_tid) {
                                t.vfork_parent_tid = Some(parent_tid);
                            }
                        }

                        // NOW unblock the child
                        crate::proc::unblock_process(child_pid);

                        // Block parent for vfork
                        if is_vfork {
                            // Commit Blocked, then recheck the completion
                            // token under the SAME THREAD_TABLE hold — see the
                            // clone(56) site above for the full race analysis
                            // and lock-ordering reasoning.
                            let mut threads = crate::proc::THREAD_TABLE.lock();
                            let child_completed = threads.iter()
                                .find(|t| t.tid == child_tid)
                                .map(|t| t.vfork_parent_tid.is_none())
                                .unwrap_or(true); // child gone (exited+reaped) ⇒ completed
                            if let Some(t) = threads.iter_mut().find(|t| t.tid == parent_tid) {
                                if child_completed {
                                    t.state = crate::proc::ThreadState::Ready;
                                    t.wake_tick = u64::MAX;
                                } else {
                                    // INVARIANT: Release-store ctx_rsp_valid=false
                                    // BEFORE Blocked — same mid-switch stale-RSP guard
                                    // as the clone3 vfork park above.
                                    t.ctx_rsp_valid.store(false, core::sync::atomic::Ordering::Release);
                                    t.state = crate::proc::ThreadState::Blocked;
                                    let now = crate::arch::x86_64::irq::get_ticks();
                                    t.wake_tick = now.saturating_add(500);
                                }
                            }
                            drop(threads);
                            if child_completed {
                                return child_pid as i64;
                            }
                            // VFORK/CANARY pre-block snapshot — see helper.
                            vfork_canary_snapshot("pre_block.clone3", pid as u32, parent_tid);
                            // Axis-N+1 three-channel stack-provenance snapshot
                            // — see clone (56) path above for the rationale.
                            #[cfg(feature = "vfork-canary-diag")]
                            {
                                crate::subsys::linux::vfork_diag::snapshot_canaries(
                                    "PRE", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_canary_walk(
                                    "PRE", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_finegrain(
                                    "pre", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_page_prov(
                                    "pre", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::store_pre_snapshot(
                                    pid, parent_tid);
                                crate::subsys::linux::vfork_diag::enter_vfork_window(
                                    pid, parent_tid);
                                crate::subsys::linux::vfork_diag::arm_master_canary_watch();
                            }
                            // D21 — arm a write-only DR on the libxul caller-
                            // frame `[rbp-8]` saved-canary slot for PID 1
                            // TID 1.  See the clone(56) site above for the
                            // rationale and PR #398 for the dispositive
                            // evidence trail.  Diagnostic-only; gated
                            // behind `d21-user-canary-watch`.
                            #[cfg(feature = "d21-user-canary-watch")]
                            crate::subsys::linux::d21_user_canary_watch::try_arm_at_vfork_preblock(
                                pid, parent_tid);
                            // D22 — PHYS_OFF channel companion to D21 for
                            // phys-aliasing detection (Wave 13).  See the
                            // clone(56) site above for rationale and PR
                            // #407 for the convergent Mechanism D verdict.
                            // Diagnostic-only; gated behind
                            // `d22-user-canary-phys`.
                            #[cfg(feature = "d22-user-canary-phys")]
                            crate::subsys::linux::d22_user_canary_phys::try_arm_at_vfork_preblock(
                                pid, parent_tid);
                            // ELF-WRITE-TRACE on 0x37e18 dropped — see
                            // clone(56) path above for the qa-verdict TODO.
                            crate::sched::schedule();
                            // VFORK/CANARY post-wake snapshot.
                            #[cfg(feature = "vfork-canary-diag")]
                            {
                                crate::subsys::linux::vfork_diag::disarm_master_canary_watch();
                                crate::subsys::linux::vfork_diag::exit_vfork_window();
                                crate::subsys::linux::vfork_diag::snapshot_canaries(
                                    "POST", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_finegrain(
                                    "post", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::snapshot_stack_page_prov(
                                    "post", pid, parent_tid);
                                crate::subsys::linux::vfork_diag::store_post_snapshot(
                                    pid, parent_tid);
                                crate::subsys::linux::vfork_diag::arm_launcher_canary_watches(
                                    pid, parent_tid);
                            }
                            vfork_canary_snapshot("post_wake.clone3", pid as u32, parent_tid);
                            // F3 code-DR watch — see clone(56) above
                            // for the rationale.  Same one-shot,
                            // PID-1-only arm site.  Diagnostic-only;
                            // gated behind `f3-codeDR-watch`.
                            #[cfg(feature = "f3-codeDR-watch")]
                            crate::subsys::linux::f3_code_dr_watch::try_arm_after_post_wake(
                                pid, parent_tid);
                        }
                        child_pid as i64
                    }
                    None => -11 // EAGAIN
                }
            } else {
                dispatch(56, clone_flags, sp, parent_tidptr, child_tidptr, tls, 0)
            }
        }

        // ─── Phase 7: Firefox dependency syscalls ─────────────────────────

        // 28: madvise(addr, len, advice)
        28 => sys_madvise(arg1, arg2, arg3),
        // 73: flock(fd, operation) — BSD-style whole-file advisory locking.
        // LOCK_SH=1 LOCK_EX=2 LOCK_UN=8 LOCK_NB=4 (Linux UAPI values).
        // Reuses the per-inode FILE_LOCKS table (F_RDLCK=0, F_WRLCK=1).
        73 => {
            const LOCK_SH: u64 = 1;
            const LOCK_EX: u64 = 2;
            const LOCK_NB: u64 = 4;
            const LOCK_UN: u64 = 8;
            let fd = arg1 as usize;
            let op = arg2;
            let nonblock = (op & LOCK_NB) != 0;
            let op_base = op & !LOCK_NB;
            let pid = crate::proc::current_pid_lockless();

            // Resolve (mount_idx, inode) from the fd.
            let (mount_idx, inode) = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                match procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.file_descriptors.get(fd)?.as_ref())
                {
                    Some(f) if !f.is_console && f.mount_idx != usize::MAX => {
                        (f.mount_idx, f.inode)
                    }
                    Some(_) => return 0, // special fd — no lock needed, succeed
                    None => return -9,   // EBADF
                }
            };

            if op_base == LOCK_UN {
                // Release any whole-file flock held by this pid on this inode.
                crate::vfs::FILE_LOCKS.lock().retain(|l| {
                    !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid)
                });
                return 0;
            }

            let lock_type: i16 = if op_base == LOCK_SH { 0 } else if op_base == LOCK_EX { 1 } else {
                crate::serial_println!("[flock] invalid op {}", op);
                return -22; // EINVAL
            };

            // Check for conflicting lock held by another pid.
            let conflict = {
                let locks = crate::vfs::FILE_LOCKS.lock();
                locks.iter().any(|l| {
                    l.mount_idx == mount_idx && l.inode == inode && l.pid != pid
                        && (lock_type == 1 /* EX */ || l.lock_type == 1 /* other holds EX */)
                })
            };
            if conflict {
                // flock() always non-blocking if LOCK_NB; otherwise would block.
                // We never sleep in kernel for F_SETLKW either — return EWOULDBLOCK.
                return -11; // EWOULDBLOCK / EAGAIN
            }

            // Acquire: replace any existing flock by this pid on this inode.
            let mut locks = crate::vfs::FILE_LOCKS.lock();
            locks.retain(|l| !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid));
            locks.push(crate::vfs::FileLockEntry {
                mount_idx, inode, pid,
                start: 0, end: 0, // whole-file: start=0, end=0 sentinel
                lock_type,
            });
            0
        }
        // 98: getrusage(who, usage)
        //
        // Per `man 2 getrusage` (Linux 5.13 / POSIX.1-2017):
        //   `who` must be one of RUSAGE_SELF (0), RUSAGE_CHILDREN (-1) or
        //   RUSAGE_THREAD (1).  Any other value yields -EINVAL.  A NULL
        //   `usage` pointer is also -EINVAL.
        //
        // struct rusage (x86_64, 144 bytes) — populated fields tracked by
        // Linux as documented in getrusage(2) "BUGS" / per-field notes:
        //   off  0 ru_utime.tv_sec     — total user-mode time
        //   off  8 ru_utime.tv_usec
        //   off 16 ru_stime.tv_sec     — total kernel-mode time
        //   off 24 ru_stime.tv_usec
        //   off 32 ru_maxrss           — peak RSS in KiB
        //   off 64 ru_minflt           — minor faults (no I/O)
        //   off 72 ru_majflt           — major faults (with I/O)
        //   off 88 ru_inblock          — block input ops (since 2.6.22)
        //   off 96 ru_oublock          — block output ops
        //   off 128 ru_nvcsw           — voluntary ctxt switches (since 2.6)
        //   off 136 ru_nivcsw          — involuntary ctxt switches
        // Fields ru_ixrss/ru_idrss/ru_isrss/ru_nswap/ru_msgsnd/ru_msgrcv/
        // ru_nsignals are documented as "currently unused on Linux" and
        // are left at zero.
        98 => {
            const RUSAGE_CHILDREN: i64 = -1;
            const RUSAGE_SELF: i64     = 0;
            const RUSAGE_THREAD: i64   = 1;
            let who = arg1 as i64;
            if who != RUSAGE_SELF && who != RUSAGE_CHILDREN && who != RUSAGE_THREAD {
                return -22; // EINVAL
            }
            // -EFAULT on NULL or kernel-VA / overflowing pointer.  Per
            // getrusage(2) ERRORS and POSIX.1-2017 §3.143 (EFAULT).
            // UserGuard's AC=1 only blocks user-mode kernel-VA writes; in
            // kernel mode (where we run with CPL=0) we must explicitly
            // reject kernel-VA pointers to prevent the user from steering
            // a kernel-page write.  CWE-822 (untrusted pointer dereference).
            if !crate::syscall::validate_user_ptr(arg2, 144) {
                return -14; // EFAULT
            }
            #[cfg(feature = "firefox-test-core")]
            crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Getrusage, arg2 as *const u8, 144);

            // RUSAGE_CHILDREN: we don't currently track per-child rollups;
            // a zero-filled struct is a conformant minimum (matches a freshly-
            // forked process that hasn't reaped any children).
            let (utime_us, max_rss_kb, minflt, inblock, oublock) = if who == RUSAGE_CHILDREN {
                (0u64, 0u64, 0u64, 0u64, 0u64)
            } else {
                // user-time proxy: total uptime in microseconds.  We do not
                // distinguish user vs kernel here — better to overstate
                // ru_utime than to lie about ru_stime, since shell `time`
                // builtins generally sum user+sys for "% CPU".
                let ticks = crate::arch::x86_64::irq::get_ticks();
                let utime_us = ticks.saturating_mul(10_000); // 100 Hz → 10 ms per tick → 10000 us
                let pid = crate::proc::current_pid_lockless();
                let (rss_kb, minflt, inb, oub) = if let Some(snap) =
                    crate::proc::proc_metrics::snapshot(pid)
                {
                    // Block ops: a block is 512 bytes per the getrusage(2)
                    // man page BUGS section (Linux man-pages 5.13).
                    let inb = snap.disk_r_bytes / 512;
                    let oub = snap.disk_w_bytes / 512;
                    // VmRSS proxy: sum of writable VMA lengths (anonymous
                    // pages we'll have actually touched).  Bounded above
                    // by the address-space VMA total.
                    let rss = {
                        let procs = crate::proc::PROCESS_TABLE.lock();
                        procs.iter().find(|p| p.pid == pid)
                            .and_then(|p| p.vm_space.as_ref().map(|v| {
                                let bytes: u64 = v.areas.iter()
                                    .filter(|a| (a.prot & crate::mm::vma::PROT_WRITE) != 0)
                                    .map(|a| a.length)
                                    .sum();
                                bytes / 1024
                            }))
                            .unwrap_or(0)
                    };
                    (rss, snap.pf_count, inb, oub)
                } else {
                    (0u64, 0u64, 0u64, 0u64)
                };
                (utime_us, rss_kb, minflt, inb, oub)
            };

            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                // Zero the whole struct first (guarantees padding is clean).
                core::ptr::write_bytes(arg2 as *mut u8, 0, 144);
                let p = arg2 as *mut i64;
                // ru_utime.tv_sec / tv_usec
                *p          = (utime_us / 1_000_000) as i64;
                *p.add(1)   = (utime_us % 1_000_000) as i64;
                // ru_stime.tv_sec / tv_usec — left at zero (no per-PID kernel-
                // time counter yet); future work would split user vs system.
                // ru_maxrss at offset 32 (index 4)
                *p.add(4)   = max_rss_kb as i64;
                // ru_minflt at offset 64 (index 8)
                *p.add(8)   = minflt as i64;
                // ru_majflt — left at zero; no per-PID major-fault counter
                // yet (would require distinguishing CoW/anon faults from
                // file-backed page-ins in the page-fault handler).
                *p.add(9)   = 0;
                // ru_inblock at offset 88 (index 11)
                *p.add(11)  = inblock as i64;
                *p.add(12)  = oublock as i64; // ru_oublock at offset 96
                // ru_nvcsw / ru_nivcsw at offsets 128, 136 — left at zero
                // (no per-PID context-switch counter; safe minimum).
            }
            0
        }
        // 99: sysinfo(info) — system statistics, per `man 2 sysinfo`.
        //
        // struct sysinfo on x86_64 is 112 bytes (NOT 64 as the legacy stub
        // assumed).  Per <sys/sysinfo.h> (Linux 2.3.23+):
        //   off  0  long          uptime      — seconds since boot
        //   off  8  unsigned long loads[3]    — 1/5/15-min load averages
        //   off 32  unsigned long totalram    — total memory (× mem_unit)
        //   off 40  unsigned long freeram     — free memory
        //   off 48  unsigned long sharedram
        //   off 56  unsigned long bufferram
        //   off 64  unsigned long totalswap
        //   off 72  unsigned long freeswap
        //   off 80  unsigned short procs      — process count
        //   off 88  unsigned long totalhigh   — high memory total (zero on x86_64)
        //   off 96  unsigned long freehigh
        //   off 104 unsigned int  mem_unit    — memory unit size in bytes
        //   off 108 char _f[0]                — no trailing padding on x86_64
        //                                       since 20 - 2*8 - 4 == 0.
        //
        // Returns -EFAULT on NULL pointer (sysinfo(2) ERRORS).
        99 => {
            // -EFAULT on NULL, kernel-VA, or overflowing pointer.  Per
            // sysinfo(2) ERRORS.  UserGuard alone is insufficient — see
            // CWE-822; kernel-mode writes ignore SMAP AC=1.
            if !crate::syscall::validate_user_ptr(arg1, 112) {
                return -14; // EFAULT
            }
            #[cfg(feature = "firefox-test-core")]
            crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Sysinfo, arg1 as *const u8, 112);

            // Live system state.
            let ticks = crate::arch::x86_64::irq::get_ticks();
            let uptime = (ticks / 100) as i64; // 100 Hz → seconds
            // PMM stats (pages, each 4 KiB).  Express in bytes for
            // consistency with mem_unit=1.
            let (total_pages, used_pages) = crate::mm::pmm::stats();
            let total_bytes = total_pages.saturating_mul(4096);
            let free_bytes  = total_pages.saturating_sub(used_pages).saturating_mul(4096);
            let procs       = crate::proc::process_count().min(u16::MAX as usize) as u16;

            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                // Zero the whole struct first (clean padding bytes).
                core::ptr::write_bytes(arg1 as *mut u8, 0, 112);
                // Byte-precise field writes (avoid pointer-arithmetic
                // index ambiguity that bit the previous version).
                let base = arg1 as *mut u8;
                core::ptr::write_unaligned(base.add(0)  as *mut i64,  uptime);
                // loads[0..3] left at zero (no load-average estimator yet).
                core::ptr::write_unaligned(base.add(32) as *mut u64, total_bytes);
                core::ptr::write_unaligned(base.add(40) as *mut u64, free_bytes);
                // sharedram, bufferram, totalswap, freeswap left at zero.
                core::ptr::write_unaligned(base.add(80) as *mut u16, procs);
                // totalhigh, freehigh left at zero (none on x86_64).
                core::ptr::write_unaligned(base.add(104) as *mut u32, 1u32); // mem_unit = 1 byte
            }
            0
        }
        // 229: clock_getres(clk_id, res) — returns 1 ns resolution for all clocks
        229 => {
            if arg2 != 0 {
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    let ts = arg2 as *mut u64;
                    *ts       = 0; // tv_sec = 0
                    *ts.add(1) = 1; // tv_nsec = 1 (nanosecond resolution)
                }
            }
            0
        }
        // 267: readlinkat(dirfd, pathname, buf, bufsiz)
        267 => {
            const AT_FDCWD: i64 = -100;
            let raw = read_cstring_from_user(arg2);
            let path_str = core::str::from_utf8(&raw).unwrap_or("");
            // If AT_FDCWD or absolute path, delegate to readlink logic
            let full_path: alloc::string::String = if arg1 as i64 == AT_FDCWD || path_str.starts_with('/') {
                alloc::string::String::from(path_str)
            } else {
                // Relative path — prepend fd's directory
                let pid = crate::proc::current_pid_lockless();
                let base = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    let proc = match procs.iter().find(|p| p.pid == pid) {
                        Some(p) => p,
                        None => return -3,
                    };
                    let idx = arg1 as usize;
                    if idx >= proc.file_descriptors.len() { return -9; }
                    match &proc.file_descriptors[idx] {
                        Some(f) => f.open_path.clone(),
                        None => return -9,
                    }
                };
                let mut s = alloc::string::String::from(base.trim_end_matches('/'));
                s.push('/');
                s.push_str(path_str);
                s
            };
            let buf = arg3 as *mut u8;
            let bufsiz = arg4 as usize;
            // /proc/self/exe, /proc/self/cwd, /proc/self/root, /proc/self/fd/<N>
            // are special-cased: they are symlinks whose targets are derived
            // from live process state, not stored on disk.  Falling through
            // to vfs::readlink() for these would return EINVAL on the symlink
            // dispatch (per proc(5)).
            let target: alloc::string::String = if full_path == "/proc/self/exe" {
                // Per readlink(2) / readlinkat(2), return ENOENT when the
                // target symlink has no recorded destination.  An empty string
                // would cause callers that slice the result without bounds
                // checking to fault or panic.  ENOENT is the canonical
                // "symlink target not available" error; callers handle it
                // gracefully via their own fallback paths.  (POSIX.1-2017.)
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                match procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.exe_path.as_ref())
                    .map(|s| s.clone())
                {
                    Some(p) => p,
                    None => return -2, // ENOENT
                }
            } else if full_path == "/proc/self/cwd" {
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid)
                    .map(|p| p.cwd.clone())
                    .unwrap_or_else(|| alloc::string::String::from("/"))
            } else if full_path == "/proc/self/root" {
                alloc::string::String::from("/")
            } else if full_path.starts_with("/proc/self/fd/") {
                let fd_part = &full_path["/proc/self/fd/".len()..];
                let fd_num = fd_part.parse::<usize>().unwrap_or(usize::MAX);
                let pid = crate::proc::current_pid_lockless();
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.file_descriptors.get(fd_num))
                    .and_then(|f| f.as_ref())
                    .map(|f| f.open_path.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| alloc::format!("/dev/fd/{}", fd_num))
            } else {
                match crate::vfs::readlink(&full_path) {
                    Ok(t) => t,
                    Err(_) => return -22,
                }
            };
            let bytes = target.as_bytes();
            let len = bytes.len().min(bufsiz);
            if len > 0 {
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len);
                }
            }
            len as i64
        }
        // 271: ppoll(fds, nfds, tmo_p, sigmask, sigsetsize) — poll with timeout+mask
        271 => {
            // Delegate to poll (syscall 7), ignoring sigmask.
            // NULL tmo_p (arg3==0) = block indefinitely (-1).
            // Non-NULL tmo_p = parse struct timespec and convert to ms.
            let timeout_ms: i64 = if arg3 == 0 {
                -1 // NULL timeout = block indefinitely (POSIX)
            } else {
                // Parse struct timespec { tv_sec: i64, tv_nsec: i64 } under
                // ONE SMAP bracket (vs the prior two-bracket shape).
                let (tv_sec_raw, tv_nsec_raw) =
                    unsafe { crate::syscall::user_read_timespec(arg3) }.unwrap_or((0, 0));
                let tv_sec = tv_sec_raw as i64;
                let tv_nsec = tv_nsec_raw as i64;
                if tv_sec == 0 && tv_nsec == 0 {
                    0 // zero timeout = return immediately
                } else {
                    // Convert to ms, minimum 1
                    (tv_sec * 1000 + tv_nsec / 1_000_000).max(1)
                }
            };
            dispatch(7, arg1, arg2, timeout_ms as u64, 0, 0, 0)
        }
        // 283: timerfd_create(clockid, flags)
        283 => sys_timerfd_create(arg1 as u32),
        // 286: timerfd_settime(fd, flags, new_value, old_value)
        286 => sys_timerfd_settime(arg1, arg2 as u32, arg3, arg4),
        // 287: timerfd_gettime(fd, curr_value)
        287 => sys_timerfd_gettime(arg1, arg2),
        // 288: accept4(sockfd, addr, addrlen, flags) — delegate to accept(43),
        // forwarding the SOCK_CLOEXEC / SOCK_NONBLOCK flags via arg4 so the
        // returned fd carries them (per `man 2 accept4`).
        288 => dispatch(43, arg1, arg2, arg3, arg4, 0, 0),
        // 289: signalfd4(fd, mask, sizemask, flags)
        289 => sys_signalfd4(arg1, arg2, arg3, arg4 as u32),
        // 253: inotify_add_watch(fd, pathname, mask)
        253 => sys_inotify_add_watch(arg1, arg2, arg3 as u32),
        // 254: inotify_rm_watch(fd, wd)
        254 => sys_inotify_rm_watch(arg1, arg2 as i32),
        // 294: inotify_init1(flags)
        294 => sys_inotify_init1(arg1 as u32),
        // 319: memfd_create(name, flags) — create an anonymous in-memory file
        319 => sys_memfd_create(arg1, arg2),
        // 23: select(nfds, readfds, writefds, exceptfds, timeout)
        23 => sys_select_linux(arg1, arg2, arg3, arg4, arg5),
        // 25: mremap(old_addr, old_size, new_size, flags, [new_addr])
        25 => sys_mremap(arg1, arg2, arg3, arg4, arg5),
        // 63: uname(buf)
        // 63: uname(buf) — user-mode entry gate; writes 325 bytes
        // (5 × 65-byte utsname fields).  CWE-823.
        63 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && !crate::syscall::validate_user_ptr(arg1, 325)
            {
                return -14;
            }
            crate::syscall::sys_uname(arg1 as *mut u8)
        }
        // 76: truncate(path, length) — POSIX truncate(2): pathname is
        // interpreted relative to the calling process's working directory
        // when it is relative.  resolve_user_path_to_owned() applies the
        // AT_FDCWD prefix in that case.
        76 => {
            let path_bytes = match resolve_user_path_to_owned(arg1) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
            let path_str = match core::str::from_utf8(&path_bytes[..len]) {
                Ok(s) => s,
                Err(_) => return -22,
            };
            match crate::vfs::truncate_path(path_str, arg2) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 90: chmod(pathname, mode) — POSIX chmod(2) §pathname resolution:
        // relative paths anchored at the working directory.
        90 => {
            let path_bytes = match resolve_user_path_to_owned(arg1) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
            let path_str = match core::str::from_utf8(&path_bytes[..len]) {
                Ok(s) => s,
                Err(_) => return -22,
            };
            match crate::vfs::chmod(path_str, arg2 as u32) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 91: fchmod(fd, mode) — set permission bits on an open fd
        91 => {
            let pid = crate::proc::current_pid_lockless();
            match crate::vfs::fchmod(pid, arg1 as usize, arg2 as u32) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 92: chown(path, uid, gid) — stub (no uid/gid yet)
        92 => 0,
        // 93: fchown(fd, uid, gid) — stub
        93 => 0,
        // 94: lchown(path, uid, gid) — stub (no symlink uid/gid yet)
        94 => 0,
        // 97: getrlimit(resource, rlim)
        97 => sys_getrlimit(arg1, arg2),
        // 109: setpgid(pid, pgid) — real: update pgid in PCB
        109 => {
            let target = if arg1 == 0 { crate::proc::current_pid_lockless() } else { arg1 };
            let new_pgid = if arg2 == 0 { target as u32 } else { arg2 as u32 };
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            match procs.iter_mut().find(|p| p.pid == target) {
                Some(p) => { p.pgid = new_pgid; 0 }
                None    => -3, // ESRCH
            }
        }
        // 111: getpgrp() — return caller's pgid
        111 => {
            let pid = crate::proc::current_pid_lockless();
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid).map(|p| p.pgid as i64).unwrap_or(pid as i64)
        }
        // 112: setsid() — become session leader with new sid/pgid
        112 => {
            let pid = crate::proc::current_pid_lockless();
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.pgid = pid as u32;
                p.sid  = pid as u32;
            }
            pid as i64
        }
        // 121: getpgid(pid) — return pgid of target (0 = caller)
        121 => {
            let target = if arg1 == 0 { crate::proc::current_pid_lockless() } else { arg1 };
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == target).map(|p| p.pgid as i64).unwrap_or(-3)
        }
        // 122: getsid(pid) — return session id
        122 => {
            let target = if arg1 == 0 { crate::proc::current_pid_lockless() } else { arg1 };
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == target).map(|p| p.sid as i64).unwrap_or(-3)
        }
        // 230: clock_nanosleep(clockid, flags, req, rem)
        230 => sys_nanosleep_linux(arg3, arg4),
        // 292: dup3(oldfd, newfd, flags) — like dup2 + optional O_CLOEXEC
        292 => {
            let ret = crate::syscall::sys_dup2(arg1 as usize, arg2 as usize);
            if ret >= 0 && (arg3 & 0x0008_0000) != 0 {
                // O_CLOEXEC: set cloexec on the new fd
                let pid = crate::proc::current_pid_lockless();
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = proc.file_descriptors.get_mut(arg2 as usize) {
                        f.cloexec = true;
                    }
                }
            }
            #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
            {
                let pid = crate::proc::current_pid_lockless();
                if pid == 1 || crate::syscall::ring::is_tracked(pid) {
                    crate::serial_println!("[FF/dup2] pid={} old={} new={} flags={:#x} ret={} (dup3)", pid, arg1, arg2, arg3, ret);
                }
            }
            ret
        }
        // 332: statx(dirfd, pathname, flags, mask, statxbuf) — extended stat
        //
        // struct statx layout (from linux/stat.h):
        //   offset  0: stx_mask       u32   — which fields are valid
        //   offset  4: stx_blksize    u32
        //   offset  8: stx_attributes u64
        //   offset 16: stx_nlink      u32
        //   offset 20: stx_uid        u32
        //   offset 24: stx_gid        u32
        //   offset 28: stx_mode       u16
        //   offset 30: __spare0       u16
        //   offset 32: stx_ino        u64
        //   offset 40: stx_size       u64
        //   offset 48: stx_blocks     u64
        //   offset 56: stx_attributes_mask u64
        332 => {
            let path_bytes = read_cstring_from_user(arg2);
            let path       = match core::str::from_utf8(&path_bytes) { Ok(s) => s, Err(_) => return -22 };
            if arg5 == 0 { return -14; } // EFAULT
            // arg4 = requested mask; we always fill all fields we have.
            // STATX_BASIC_STATS = 0x7ff covers mode, nlink, uid, gid, ino, size, etc.
            let _req_mask = arg4 as u32;
            match crate::vfs::stat(path) {
                Ok(st) => {
                    // struct statx is 256 bytes; zero the whole thing first
                    let base = arg5 as *mut u8;
                    #[cfg(feature = "firefox-test-core")]
                    crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Statx, base, 256);
                    let mode: u16 = match st.file_type {
                        crate::vfs::FileType::Directory => 0o040_755,
                        crate::vfs::FileType::SymLink   => 0o120_777,
                        _                               => 0o100_644,
                    };
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::write_bytes(base, 0, 256);
                        // stx_mask (offset 0): populate BASIC_STATS fields
                        core::ptr::write(base.add(0) as *mut u32, 0x7ff_u32);
                        // stx_blksize (offset 4)
                        core::ptr::write(base.add(4) as *mut u32, 4096_u32);
                        // stx_nlink (offset 16)
                        core::ptr::write(base.add(16) as *mut u32, 1_u32);
                        // stx_mode (offset 28): file type bits + permission bits
                        core::ptr::write(base.add(28) as *mut u16, mode);
                        // stx_ino (offset 32)
                        core::ptr::write(base.add(32) as *mut u64, st.inode);
                        // stx_size (offset 40)
                        core::ptr::write(base.add(40) as *mut u64, st.size);
                    }
                    0
                }
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }

        // ─── Phase 1 batch 2: small stubs / wrappers for bash + coreutils ─────

        // 22: pipe(pipefd[2]) — create a pipe, writing int pipefd[2] (8 bytes)
        // to the user buffer.  pipe(2): https://man7.org/linux/man-pages/man2/pipe.2.html
        // The ABI is `int pipefd[2]` = 2 × 4-byte ints = 8 bytes total.
        22 => {
            if !crate::syscall::user_ptr_check_bypassed()
                && !crate::syscall::validate_user_ptr(arg1, 8)
            {
                return -14;
            }
            crate::syscall::sys_pipe(arg1 as *mut u32)
        }
        // 26: msync(addr, length, flags) — writeback not yet implemented.
        // Returning 0 silently is dangerous (caller believes data is durable).
        // Return ENOSYS until a real writeback path exists.
        26 => {
            crate::serial_println!("[msync] {:#x} len={} flags={} -> ENOSYS (no writeback infrastructure)", arg1, arg2, arg3);
            -38 // ENOSYS
        }
        // 27: mincore(addr, length, vec) — report all pages as resident
        27 => {
            let pages = ((arg2 + 0xFFF) / 0x1000) as usize;
            if arg3 != 0 && crate::syscall::validate_user_ptr(arg3, pages) {
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::write_bytes(arg3 as *mut u8, 1, pages);
                }
            }
            0
        }
        // 95: umask(mask) — set file creation mask
        95 => crate::syscall::sys_umask(arg1 as u32),
        // 100: times(buf) — CPU usage times; return zero struct
        100 => {
            if arg1 != 0 && crate::syscall::validate_user_ptr(arg1, 32) {
                #[cfg(feature = "firefox-test-core")]
                crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Times, arg1 as *const u8, 32);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::write_bytes(arg1 as *mut u8, 0, 32);
                }
            }
            0
        }
        // 105: setuid(uid) — stub (always root in AstryxOS)
        105 => 0,
        // 106: setgid(gid) — stub
        106 => 0,
        // 114: setreuid(ruid, euid) — stub
        114 => 0,
        // 115: getgroups(size, list) — no supplemental groups
        115 => 0,
        // 116: setgroups(size, list) — stub success
        116 => 0,
        // 117: setresuid(ruid, euid, suid) — stub
        117 => 0,
        // 118: getresuid(ruid, euid, suid) — all zero (root)
        118 => {
            for ptr in [arg1, arg2, arg3] {
                if ptr != 0 && crate::syscall::validate_user_ptr(ptr, 4) {
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::write(ptr as *mut u32, 0u32);
                    }
                }
            }
            0
        }
        // 119: setresgid(rgid, egid, sgid) — stub
        119 => 0,
        // 120: getresgid(rgid, egid, sgid) — all zero
        120 => {
            for ptr in [arg1, arg2, arg3] {
                if ptr != 0 && crate::syscall::validate_user_ptr(ptr, 4) {
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::write(ptr as *mut u32, 0u32);
                    }
                }
            }
            0
        }
        // 127: rt_sigpending(set, sigsetsize) — stub: no pending signals
        127 => {
            if arg1 != 0 && crate::syscall::validate_user_ptr(arg1, arg2 as usize) {
                #[cfg(feature = "firefox-test-core")]
                crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Memset, arg1 as *const u8, arg2 as usize);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::write_bytes(arg1 as *mut u8, 0, arg2 as usize);
                }
            }
            0
        }
        // 128: rt_sigtimedwait(set, info, timeout, sigsetsize) — stub EINTR
        128 => -4, // EINTR
        // 130: rt_sigsuspend(mask, sigsetsize) — yield + EINTR
        130 => {
            crate::sched::yield_cpu();
            -4 // EINTR
        }
        // 161: chroot(path) — per-task VFS root pivot not yet implemented.
        // Silent success was a security hazard: sandboxes believed they were jailed.
        // Return ENOSYS until per-task root tracking is added to task_struct.
        161 => {
            crate::serial_println!("[chroot] -> ENOSYS (per-task root not implemented)");
            -38 // ENOSYS
        }
        // 162: sync() — flush filesystem
        162 => { crate::vfs::sync_all(); 0 }
        // 163: acct(filename) — stub  
        163 => -38, // ENOSYS
        // 164: settimeofday — stub
        164 => 0,
        // 165: mount(source, target, fstype, flags, data)
        165 => {
            let source_raw = read_cstring_from_user(arg1);
            let target_raw = read_cstring_from_user(arg2);
            let fstype_raw = read_cstring_from_user(arg3);
            let flags = arg4;
            let data_raw  = read_cstring_from_user(arg5);
            let source = core::str::from_utf8(&source_raw).unwrap_or("");
            let target = core::str::from_utf8(&target_raw).unwrap_or("");
            let fstype = core::str::from_utf8(&fstype_raw).unwrap_or("");
            let data   = core::str::from_utf8(&data_raw).unwrap_or("");
            crate::vfs::sys_mount(source, target, fstype, flags, data)
        }
        // 166: umount(target)
        166 => {
            let target_raw = read_cstring_from_user(arg1);
            let target = core::str::from_utf8(&target_raw).unwrap_or("");
            crate::vfs::sys_umount(target, 0)
        }
        // 167: swapon — stub ENOSYS (no swap on AstryxOS)
        167 => -38, // ENOSYS
        // 168: swapoff(path) — UAPI 168; previously mis-dispatched to poll (syscall 7)
        // AstryxOS has no swap; return ENOSYS so callers get a clear failure.
        168 => {
            crate::serial_println!("[SYSCALL] swapoff (168) not implemented — ENOSYS");
            -38 // ENOSYS
        }
        // 169: umount2(target, flags)
        169 => {
            let target_raw = read_cstring_from_user(arg1);
            let target = core::str::from_utf8(&target_raw).unwrap_or("");
            let flags  = arg2;
            crate::vfs::sys_umount(target, flags)
        }
        // 185: security (LSM hook entry point) — UAPI 185; previously mis-assigned to rt_sigaction.
        // No application legitimately calls rt_sigaction via 185; real rt_sigaction is syscall 13.
        185 => {
            crate::serial_println!("[SYSCALL] security (185) not implemented — ENOSYS");
            -38 // ENOSYS
        }
        // 192-199: extended-attribute syscalls (*xattr family) — ENODATA (no xattrs).
        // Previously this arm incorrectly swallowed 200 (tkill) and 201 (time) too,
        // which made glibc's `time(NULL)` fallback (when no vDSO is present) return
        // -1 with errno=ENODATA, and poisoned pthread's internal tkill() usage.
        // See arch-syscall.h: 192 lgetxattr .. 199 fremovexattr; 200 tkill; 201 time.
        192 | 193 | 194 | 195 | 196 | 197 | 198 | 199 => -61, // ENODATA
        // 200: tkill(tid, sig) — send signal `sig` to the single thread `tid`.
        // tkill(2) addresses a thread directly by its kernel thread id (the
        // obsolete-but-still-used predecessor of tgkill(2)).  musl's raise(3)
        // and the abort(3) re-raise path issue tkill(self->tid, sig); returning
        // ENOSYS here breaks that path (a crashing thread cannot re-raise to
        // produce its default-action termination).  AstryxOS delivers signals
        // at process granularity (one signal_state per process), so resolve the
        // target thread's owning process and dispatch via the same path as
        // tgkill(2) (signal::kill).  Per tkill(2): ESRCH if no such thread.
        200 => {
            let tid = arg1;
            let sig = arg2 as u8;
            let owner_pid = crate::proc::pid_for_tid(tid);
            if owner_pid == 0 {
                -3 // ESRCH — no thread carries this tid
            } else {
                crate::signal::kill(owner_pid, sig)
            }
        }
        // 201: time(tloc) — seconds since Epoch; optionally write to *tloc.
        // glibc calls this as a vDSO fallback; returning an error here makes
        // `time(NULL)` appear to fail with the kernel's errno, confusing callers.
        201 => {
            // Per `man 2 time`: seconds since the UNIX epoch — must agree
            // with __vdso_time / clock_gettime(CLOCK_REALTIME).  See
            // `kernel/src/proc/vdso.rs::wall_secs_at_boot()` for the
            // canonical formula.
            let ticks = crate::arch::x86_64::irq::get_ticks();
            let wall_secs: i64 = crate::proc::vdso::wall_secs_at_boot()
                .saturating_add(ticks / 100) as i64;
            if arg1 != 0 {
                // Validate the user pointer before writing — a userspace
                // caller passing a kernel address (or any non-writable
                // user address) must observe EFAULT, not corrupt kernel
                // memory or trigger a page fault inside the syscall arm.
                if !crate::syscall::validate_user_ptr(arg1, 8) {
                    return -14; // EFAULT
                }
                // SMAP bracket — the slice materialisation and the
                // copy_from_slice write below both touch a user page
                // (PTE.U=1).  Per Intel SDM Vol. 3A §4.6 the supervisor
                // must hold EFLAGS.AC=1 to issue these stores.  UserGuard
                // RAII issues STAC on construction and CLAC on drop, so
                // the bracket covers the write regardless of fault unwind.
                // glibc's `time(t)` vDSO fallback (man 2 time) takes this
                // path whenever a userspace caller passes a non-NULL tloc.
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    let buf = core::slice::from_raw_parts_mut(arg1 as *mut u8, 8);
                    buf.copy_from_slice(&wall_secs.to_le_bytes());
                }
            }
            wall_secs
        }
        // 270: pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
        270 => sys_select_linux(arg1, arg2, arg3, arg4, arg5),
        // 285: fallocate(fd, mode, offset, len) — stub success
        285 => 0,
        // 295: preadv(fd, iov, iovcnt, offset_lo, offset_hi)
        // Scatter-gather positioned read; offset = (offset_hi << 32) | offset_lo on x86-64
        // but Linux x86_64 passes the offset as a single i64 in arg4 (lo) with arg5=0.
        295 => sys_preadv(arg1, arg2, arg3, arg4 as i64),
        // 296: pwritev(fd, iov, iovcnt, offset)
        296 => sys_pwritev(arg1, arg2, arg3, arg4 as i64),
        // 437: openat2(dirfd, path, how, size) — forward to openat (ignore resolve flags)
        437 => {
            // openat2 struct how: { flags: u64, mode: u64, resolve: u64 }
            // arg1=dirfd, arg2=path, arg3=*how, arg4=sizeof(how)
            //
            // SMAP bracket — both reads target user memory.  Validate the
            // range up front (16 B covers flags+mode), then dereference
            // under a single UserGuard.  Per Intel SDM Vol. 3A §4.6 and
            // openat2(2) man page (which specifies a `struct open_how`).
            let (how_flags, how_mode) = if arg3 != 0 {
                if !crate::syscall::validate_user_ptr(arg3, 16) {
                    return -14; // EFAULT
                }
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    (core::ptr::read_unaligned(arg3 as *const u64),
                     core::ptr::read_unaligned((arg3 + 8) as *const u64))
                }
            } else {
                (0, 0o644)
            };
            dispatch(257, arg1, arg2, how_flags, how_mode, 0, 0) // openat
        }
        // 316: renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        316 => {
            let old_raw = read_cstring_from_user(arg2);
            let new_raw = read_cstring_from_user(arg4);
            let old_str = core::str::from_utf8(&old_raw).unwrap_or("");
            let new_str = core::str::from_utf8(&new_raw).unwrap_or("");
            match crate::vfs::rename(old_str, new_str) {
                Ok(()) => 0,
                Err(e) => crate::subsys::linux::errno::vfs_err(e),
            }
        }
        // 436: close_range(first, last, flags) — close a range of fds
        // (also mapped at 355 for backwards compat, but 436 is the correct x86_64 number)
        436 | 355 => {
            let pid = crate::proc::current_pid_lockless();
            let first = arg1 as usize;
            let last = (arg2 as usize).min(4095);
            for fd in first..=last {
                let _ = crate::vfs::close(pid, fd);
            }
            0
        }
        // 140: getpriority(which, who) — return nice value (always 0 = normal)
        // Linux returns 20-nice (range 1-40), so 20 = nice 0.
        140 => 20,
        // 141: setpriority(which, who, prio) — no-op
        141 => 0,
        // 149: mlock(addr, len)   — no-op (no swapping in AstryxOS)
        149 => 0,
        // 150: munlock(addr, len) — no-op
        150 => 0,
        // 151: mlockall(flags)    — no-op
        151 => 0,
        // 152: munlockall()       — no-op
        152 => 0,
        // 322: execveat(dirfd, path, argv, envp, flags)
        322 => {
            // If path is empty and AT_EMPTY_PATH (0x1000) set, exec fd directly — unsupported
            let path_bytes = read_cstring_from_user(arg2);
            let path_str   = core::str::from_utf8(&path_bytes).unwrap_or("");
            if path_str.is_empty() {
                return -38; // ENOSYS — fd-based execveat not supported
            }
            // Otherwise delegate to execve (59) ignoring dirfd (absolute path required)
            dispatch(59, arg2, arg3, arg4, 0, 0, 0)
        }
        // 326: copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
        // Delegate to sendfile (40); arg1=fd_in, arg3=fd_out, arg2=off_in, arg5=len
        326 => sys_sendfile(arg3 as usize, arg1 as usize, arg2, arg5 as usize),
        // 282: signalfd(fd, *mask, sizemask) — legacy form, no flags argument.
        // Per signalfd(2): "signalfd() was added to Linux in kernel 2.6.22;
        // [signalfd4] supports a flags argument."  Functionally equivalent to
        // signalfd4(fd, mask, sizemask, 0); musl posix_spawn's cancellation
        // path and older glibc binaries still issue 282 directly.
        282 => sys_signalfd4(arg1, arg2, arg3, 0),
        // 424: pidfd_send_signal(pidfd, sig, *info, flags) — ENOSYS until
        // pidfd objects exist.  Returning -38 here forces tokio's
        // `tokio::process::Child::kill` fallback path (kill(2) via the
        // child's recorded PID), which is the canonical behaviour on
        // pre-5.1 Linux per pidfd_send_signal(2) NOTES.
        424 => -38,
        // 434: pidfd_open(pid, flags) — ENOSYS until pidfd objects exist.
        // Per pidfd_open(2): "Returns a file descriptor that refers to the
        // process whose PID is specified in pid."  Tokio's `signal::ctrl_c`
        // and `process::Child::wait` reactor paths fall back to signalfd +
        // waitpid when this returns ENOSYS, both of which are plumbed.
        434 => {
            crate::serial_println!("[SYSCALL/Linux] pidfd_open(pid={}, flags={:#x}) — ENOSYS", arg1, arg2);
            -38 // ENOSYS
        }
        // 441: epoll_pwait2(epfd, events, maxevents, *timespec, *sigmask, sigsetsize)
        // Per epoll_pwait2(2) (Linux 5.11+): "epoll_pwait2() … takes a
        // pointer to a timespec structure instead of milliseconds, allowing
        // sub-millisecond precision."  Internally bounds-checks the
        // user-supplied timespec, converts to whole milliseconds (matching
        // our 100 Hz timer resolution), and delegates to sys_epoll_wait.
        // The sigmask arg (arg5/arg6) is accepted-and-ignored as on
        // epoll_pwait (sc 281) — see that arm's comment.
        441 => {
            let timeout_ms: i32 = if arg4 == 0 {
                -1 // NULL timespec → block indefinitely per spec
            } else {
                if !crate::syscall::validate_user_ptr(arg4, 16) {
                    return -14; // EFAULT
                }
                let (tv_sec, tv_nsec) = unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    let p = arg4 as *const i64;
                    (core::ptr::read_unaligned(p), core::ptr::read_unaligned(p.add(1)))
                };
                if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
                    return -22; // EINVAL
                }
                // Convert to whole ms, saturating to i32::MAX (~24.8 days).
                // Round up to ensure caller's deadline isn't crossed before
                // we even attempt the first poll on sub-tick timeouts.
                let ms = (tv_sec as u64)
                    .saturating_mul(1000)
                    .saturating_add(((tv_nsec as u64) + 999_999) / 1_000_000);
                ms.min(i32::MAX as u64) as i32
            };
            sys_epoll_wait(arg1 as usize, arg2, arg3 as usize, timeout_ms)
        }
        // 443-445: landlock_* — ENOSYS
        443 | 444 | 445 => -38,

        // 85: creat(pathname, mode) — trivially: open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
        85 => {
            // Linux flags: O_CREAT=0x40, O_WRONLY=1, O_TRUNC=0x200 → combined = 0x241
            sys_open_linux(arg1, 0x241, arg2)
        }
        // 78: getdents(fd, buf, count) — 32-bit inode/offset variant of getdents64
        78 => sys_getdents(arg1, arg2, arg3),
        // 37: alarm(seconds) — schedule SIGALRM after `seconds` wall-clock seconds.
        // Returns previous alarm remaining seconds (0 if none).
        37 => sys_alarm(arg1),
        // 38: setitimer(which, new_value, old_value) — interval timer
        38 => sys_setitimer(arg1, arg2, arg3),
        // 36: getitimer(which, curr_value) — read current interval timer
        36 => sys_getitimer(arg1, arg2),
        // 258: mkdirat(dirfd, pathname, mode)
        258 => sys_mkdirat(arg1, arg2, arg3),
        // 263: unlinkat(dirfd, pathname, flags)
        263 => sys_unlinkat(arg1, arg2, arg3),
        // 264: renameat(olddirfd, oldpath, newdirfd, newpath)
        264 => sys_renameat(arg1, arg2, arg3, arg4),
        // 265: linkat(olddirfd, oldpath, newdirfd, newpath, flags) — hard link.
        265 => sys_linkat(arg1, arg2, arg3, arg4, arg5),

        // ─── T1 batch 2 additions ─────────────────────────────────────────

        // 297: rt_tgsigqueueinfo(tgid, tid, sig, uinfo)
        // Deliver signal `sig` to thread `tid` in thread group `tgid`.
        // The siginfo_t user pointer is accepted but we delegate to the
        // existing kill primitive which carries no extra info payload.
        297 => {
            // arg1=tgid, arg2=tid, arg3=sig, arg4=uinfo*
            // sig==0 is a validity probe — just return 0.
            if arg3 == 0 { return 0; }
            crate::signal::kill(arg1, arg3 as u8)
        }

        // 300: fanotify_init(flags, event_f_flags) — stub ENOSYS
        // 301: fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname) — stub ENOSYS
        // Firefox and common tools probe fanotify presence via -ENOSYS and fall back.
        300 | 301 => {
            crate::serial_println!("[SYSCALL/Linux] fanotify syscall {} — ENOSYS (no fanotify support)", num);
            -38 // ENOSYS
        }

        // 306: syncfs(fd) — flush the filesystem containing fd.
        // We have no async writeback queue; just return success so callers
        // (e.g. package managers) don't abort.
        306 => {
            crate::serial_println!("[SYSCALL/Linux] syncfs(fd={}) — returning 0 (no writeback queue)", arg1);
            0
        }

        // 329: pkey_mprotect(addr, len, prot, pkey) — delegate to mprotect, ignore pkey.
        // 330: pkey_alloc(flags, access_rights) — stub; returns pkey 0 (default key).
        // 331: pkey_free(pkey) — pkey_free(0) is invalid (can't free default key).
        // PKE (CR4.PKE) is not enabled; these stubs satisfy glibc's cpuid probe path.
        329 => sys_mprotect(arg1, arg2, arg3), // delegate; arg4 pkey silently ignored
        330 => {
            // flags and access_rights are reserved; must be 0.
            if arg1 != 0 || arg2 != 0 { return -22; } // EINVAL
            0 // return pkey 0 (the default protection key)
        }
        331 => {
            // pkey 0 is the default key; it may never be freed.
            if arg1 == 0 { return -22; } // EINVAL
            -22 // EINVAL — we only ever return key 0, so any free is invalid
        }

        // Explicit ENOSYS for syscalls that would silently fail otherwise
        // (give the process a chance to fall back rather than misinterpreting 0)
        210 | 211 | 214 | 215 | 216 | 237 | 255 => -38, // ENOSYS

        _ => {
            crate::serial_println!("[SYSCALL/Linux] Unknown Linux syscall: {}", num);
            -38 // ENOSYS
        }
    }
}

// ── Linux-ABI syscall wrappers ──────────────────────────────────────────────

/// nanosleep(req, rem) — struct timespec { tv_sec: i64, tv_nsec: i64 }.
/// Also used by clock_nanosleep() (syscall 230) for the `req` field.
/// Timer resolution: 100 Hz → 1 tick = 10 ms.
fn sys_nanosleep_linux(req_ptr: u64, _rem_ptr: u64) -> i64 {
    if req_ptr == 0 {
        // NULL req pointer — invalid, but yield the CPU first so callers that
        // use nanosleep(NULL,NULL) as a cooperative yield hint don't busy-spin.
        crate::sched::yield_cpu();
        return -22; // EINVAL
    }
    if !crate::syscall::validate_user_ptr(req_ptr, 16) { return -14; } // EFAULT
    let (tv_sec, tv_nsec) = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        let p = req_ptr as *const i64;
        (core::ptr::read_unaligned(p), core::ptr::read_unaligned(p.add(1)))
    };
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return -22; // EINVAL
    }
    // Convert timespec → timer ticks (100 Hz, 10 ms/tick), rounded up.
    let ms = (tv_sec as u64) * 1000 + (tv_nsec as u64) / 1_000_000;
    let ticks = (ms + 9) / 10;
    if ticks > 0 {
        crate::proc::sleep_ticks(ticks);
    } else {
        // Zero-duration sleep — still yield so other threads can run.
        crate::sched::yield_cpu();
    }
    0
}

/// getrlimit(resource, rlim) — fill `struct rlimit { rlim_cur, rlim_max }` (2×u64).
/// Also called by prlimit64() for GET operations.
fn sys_getrlimit(resource: u64, rlim_ptr: u64) -> i64 {
    if !crate::syscall::validate_user_ptr(rlim_ptr, 16) { return -14; } // EFAULT
    const RLIM_INFINITY: u64 = u64::MAX;
    // Hard limits (max) are fixed; soft limits come from per-process rlimits_soft.
    let hard: u64 = match resource {
        3  => RLIM_INFINITY,        // RLIMIT_STACK hard = unlimited
        7  => 65536,                // RLIMIT_NOFILE hard
        _  => RLIM_INFINITY,
    };
    // Read per-process soft limit.
    let soft = if resource < 16 {
        let pid = crate::proc::current_pid_lockless();
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid)
            .map(|p| p.rlimits_soft[resource as usize])
            .unwrap_or(RLIM_INFINITY)
    } else {
        RLIM_INFINITY
    };
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        let p = rlim_ptr as *mut u64;
        core::ptr::write_unaligned(p,        soft);
        core::ptr::write_unaligned(p.add(1), hard);
    }
    0
}

/// select(nfds, readfds, writefds, exceptfds, timeout_tv)
///
/// fd_set is a bitmask: bit `n` set means fd `n` is of interest.
/// On return, unready bits are cleared.  Returns total ready fd count.
/// Non-blocking for regular files (always ready); single yield for sockets/pipes.
fn sys_select_linux(
    nfds: u64, readfds: u64, writefds: u64, _exceptfds: u64, timeout: u64,
) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let nfds = nfds.min(1024) as usize;
    let mut ready = 0i64;

    // When called from kernel-test dispatch (dispatch_linux_kernel / KernelDispatchGuard),
    // the fd_set pointers may be kernel-resident stack/heap addresses that fail
    // validate_user_ptr's user-range check (ptr < KERNEL_VIRT_BASE).  In that case
    // we skip both the range check and the SMAP guard — we are already in ring-0
    // with full kernel-VA access.  Real user-mode calls always arrive without the
    // bypass flag and get the full SMAP discipline.
    //
    // Intel SDM Vol. 3A §4.6.1: STAC/CLAC (SMAP) guards are only needed when
    // ring-0 accesses user-mode (below KERNEL_VIRT_BASE) virtual addresses.
    // Accesses to kernel-mode addresses never require STAC.
    let kernel_dispatch = crate::syscall::user_ptr_check_bypassed();

    // Read one bit from an fd_set pointer.  Handles both the user-pointer path
    // (validate + SMAP guard) and the kernel-dispatch bypass path (direct read).
    // Safety: caller ensures `ptr` is non-null and `ptr + byte_off` is readable.
    #[inline(always)]
    fn fdset_read_bit(ptr: u64, byte_off: u64, bit: u8, kernel_dispatch: bool) -> bool {
        if kernel_dispatch {
            // Kernel address — no SMAP guard needed; no user-range check.
            unsafe { *((ptr + byte_off) as *const u8) & bit != 0 }
        } else {
            crate::syscall::validate_user_ptr(ptr + byte_off, 1)
                && unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    *((ptr + byte_off) as *const u8) & bit != 0
                }
        }
    }

    // Clear one bit in an fd_set pointer.
    // Safety: caller ensures `ptr` is non-null and `ptr + byte_off` is writable.
    #[inline(always)]
    fn fdset_clear_bit(ptr: u64, byte_off: u64, bit: u8, kernel_dispatch: bool) {
        if kernel_dispatch {
            unsafe { *((ptr + byte_off) as *mut u8) &= !bit; }
        } else {
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                *((ptr + byte_off) as *mut u8) &= !bit;
            }
        }
    }

    for fd in 0..nfds {
        let byte_off = (fd / 8) as u64;
        let bit      = 1u8 << (fd % 8);

        let r_req = readfds  != 0 && fdset_read_bit(readfds,  byte_off, bit, kernel_dispatch);
        let w_req = writefds != 0 && fdset_read_bit(writefds, byte_off, bit, kernel_dispatch);

        if !r_req && !w_req { continue; }

        // Determine readiness (mirrors poll logic)
        let can_read = if fd <= 1 {
            fd == 0 // stdin always readable; stdout/stderr not
        } else if crate::syscall::is_eventfd_fd(pid, fd) {
            crate::ipc::eventfd::is_readable(crate::syscall::get_eventfd_id(pid, fd))
        } else if crate::syscall::is_pipe_fd(pid, fd) {
            // Per POSIX `select(2)`: a pipe read-end whose writer has
            // closed must be reported readable so the userspace `read()`
            // can return 0 (EOF).  Otherwise glibc / Firefox would block
            // forever waiting for data that can never arrive.
            let pid_id = crate::syscall::get_pipe_id(pid, fd);
            crate::ipc::pipe::pipe_has_data(pid_id)
                || crate::ipc::pipe::pipe_writer_closed(pid_id)
        } else if crate::syscall::is_unix_socket_fd(pid, fd) {
            let uid = crate::syscall::get_unix_socket_id(pid, fd);
            // A reached SCM_RIGHTS batch (control-only fd handoff, iov_len==0)
            // is a readable message per recvmsg(2) / unix(7) / POSIX.1-2017,
            // even with zero data bytes — surface it as select(2) readable.
            crate::net::unix::has_data(uid)
                || crate::net::unix::has_pending(uid)
                || crate::syscall::has_scm_deliverable(
                    uid, crate::net::unix::recv_consumed(uid))
        } else if crate::syscall::is_socket_fd(pid, fd) {
            crate::net::socket::socket_has_data(crate::syscall::get_socket_id(pid, fd))
        } else if crate::syscall::is_timerfd_fd(pid, fd) {
            crate::ipc::timerfd::is_readable(crate::syscall::get_timerfd_id(pid, fd))
        } else if crate::syscall::is_signalfd_fd(pid, fd) {
            crate::ipc::signalfd::is_readable(crate::syscall::get_signalfd_id(pid, fd))
        } else if crate::syscall::is_inotify_fd(pid, fd) {
            crate::ipc::inotify::is_readable(crate::syscall::get_inotify_id(pid, fd))
        } else {
            true // regular file: always ready
        };
        let can_write = fd != 0; // stdin (fd=0) not writable; stdout/stderr/others are

        if r_req {
            if can_read { ready += 1; }
            else {
                // Clear unready bit
                fdset_clear_bit(readfds, byte_off, bit, kernel_dispatch);
            }
        }
        if w_req {
            if can_write { ready += 1; }
            else {
                fdset_clear_bit(writefds, byte_off, bit, kernel_dispatch);
            }
        }
    }

    // Read-only readiness probe: returns true if any still-requested fd is
    // currently ready, WITHOUT clearing any fd_set bits.  Used as the
    // recheck-under-lock predicate for `wait_poll_event` so the
    // check-and-park lost-wakeup window is closed without destructively
    // mutating the caller's fd_set during the recheck (the authoritative
    // bit-clearing `do_rescan` runs only after we decide to return).
    let probe_ready = || -> bool {
        for fd in 0..nfds {
            let byte_off = (fd / 8) as u64;
            let bit      = 1u8 << (fd % 8);
            let r_req = readfds  != 0 && fdset_read_bit(readfds,  byte_off, bit, kernel_dispatch);
            let w_req = writefds != 0 && fdset_read_bit(writefds, byte_off, bit, kernel_dispatch);
            if !r_req && !w_req { continue; }
            let revents = crate::syscall::poll_revents(pid, fd, if r_req { 0x0001 } else { 0x0004 });
            const READABLE_MASK: u16 = 0x0001 | 0x0010;
            if r_req && revents & READABLE_MASK != 0 { return true; }
            if w_req && revents & 0x0004 != 0 { return true; }
        }
        false
    };

    let do_rescan = |ready: &mut i64| {
        *ready = 0;
        for fd in 0..nfds {
            let byte_off = (fd / 8) as u64;
            let bit      = 1u8 << (fd % 8);
            let r_req = readfds  != 0 && fdset_read_bit(readfds,  byte_off, bit, kernel_dispatch);
            let w_req = writefds != 0 && fdset_read_bit(writefds, byte_off, bit, kernel_dispatch);
            if !r_req && !w_req { continue; }
            let revents = crate::syscall::poll_revents(pid, fd, if r_req { 0x0001 } else { 0x0004 });
            // Per POSIX `select(2)`: a hung-up pipe read-end is reported
            // readable so the userspace `read()` returns 0 (EOF).  POLLHUP
            // (0x0010) here therefore counts as a readable signal in
            // addition to POLLIN (0x0001).
            const READABLE_MASK: u16 = 0x0001 | 0x0010;
            if r_req && revents & READABLE_MASK != 0 { *ready += 1; }
            else if r_req {
                fdset_clear_bit(readfds, byte_off, bit, kernel_dispatch);
            }
            if w_req && revents & 0x0004 != 0 { *ready += 1; }
            else if w_req {
                fdset_clear_bit(writefds, byte_off, bit, kernel_dispatch);
            }
        }
    };

    if ready == 0 {
        // Per `man 2 select`: NULL timeout blocks indefinitely; a timeval of
        // {0,0} returns immediately; otherwise block bounded by the timeval.
        // Returning 0 early (the previous "yield 64 times" behaviour) caused
        // applications using the canonical self-pipe-wakeup pattern to
        // busy-loop instead of blocking until the peer thread wrote.
        crate::x11::poll();
        let timeout_ms: i64 = if timeout == 0 {
            -1 // NULL → infinite
        } else if !kernel_dispatch && !crate::syscall::validate_user_ptr(timeout, 16) {
            -1 // bad user pointer — treat as infinite to be conservative
        } else {
            // struct timeval { tv_sec: i64, tv_usec: i64 } on x86_64.
            let (tv_sec, tv_usec) = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                (core::ptr::read_unaligned(timeout as *const i64),
                 core::ptr::read_unaligned((timeout + 8) as *const i64))
            };
            if tv_sec == 0 && tv_usec == 0 {
                0
            } else {
                let ms = tv_sec.saturating_mul(1000)
                    .saturating_add(tv_usec / 1000);
                ms.max(1)
            }
        };

        if timeout_ms != 0 {
            let deadline_tick = if timeout_ms < 0 {
                u64::MAX
            } else {
                let now = crate::arch::x86_64::irq::get_ticks();
                now.saturating_add(((timeout_ms as u64) / 10).max(1))
            };
            // Per-object interest set: every fd this select(2) call requested
            // (read OR write side) maps to its concrete readiness object, so the
            // per-object poll-bell drain wakes this caller only on edges of the
            // exact fds it watches (intra-class herd collapse).  Computed once —
            // the fd_set membership is fixed for the wait (do_rescan only
            // *clears* bits on ready fds it returns, after the wait completes).
            // Conservative superset: an unclassifiable fd ⇒ wake-on-class.
            let (bell_mask, bell_objects) = {
                let mut fds: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
                for fd in 0..nfds {
                    let byte_off = (fd / 8) as u64;
                    let bit = 1u8 << (fd % 8);
                    let r_req = readfds != 0
                        && fdset_read_bit(readfds, byte_off, bit, kernel_dispatch);
                    let w_req = writefds != 0
                        && fdset_read_bit(writefds, byte_off, bit, kernel_dispatch);
                    if r_req || w_req {
                        fds.push(fd);
                    }
                }
                bell_watch_for_fds(pid, fds.into_iter())
            };
            loop {
                // Park on the global poll bell — see the matching change
                // in sys_poll for why this replaces the prior 10 ms tick
                // sleep.  The bell wakes us when any pipe/eventfd state
                // change occurs; the scheduler tick wakes us at the
                // deadline.  Either path drops back into the rescan.
                //
                // `probe_ready` is re-run under the POLL_BELL lock before
                // committing to park (prepare-to-wait), closing the
                // check-and-park lost-wakeup window; it is read-only so the
                // authoritative bit-clearing `do_rescan` below stays the
                // single fd_set mutator.
                let ready_in_window =
                    crate::ipc::waitlist::wait_poll_event_obj(
                        deadline_tick, bell_mask, &bell_objects, &probe_ready);
                if !ready_in_window {
                    crate::x11::poll();
                }
                do_rescan(&mut ready);
                if ready > 0 { break; }
                if signal_pending(pid) { return -4; } // EINTR
                let now = crate::arch::x86_64::irq::get_ticks();
                if now >= deadline_tick { break; }
            }
        }
    }
    ready
}

/// W215 telemetry: number of MADV_DONTNEED/MADV_FREE per-page zero-fills
/// suppressed by the file-backed guard.  Read from kdb / serial logging.
#[cfg(feature = "firefox-test-core")]
static MADV_ZERO_SUPPRESSED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Number of zero-fills the W215 file-backed guard has suppressed.  Always 0
/// on non-firefox-test builds.
#[cfg(feature = "firefox-test-core")]
pub fn madv_zero_suppressed_count() -> u64 {
    MADV_ZERO_SUPPRESSED.load(core::sync::atomic::Ordering::Relaxed)
}

/// madvise(addr, len, advice) — memory usage hint.
///
/// MADV_DONTNEED (4) and MADV_FREE (8): free physical pages in range so the
/// next access re-allocates a zero-filled page. All other values are no-ops.
fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    const MADV_DONTNEED: u64 = 4;
    const MADV_FREE:     u64 = 8;
    if advice != MADV_DONTNEED && advice != MADV_FREE { return 0; }
    if len == 0 { return 0; }

    let pid = crate::proc::current_pid_lockless();
    let start = addr & !0xFFF;
    let end   = (addr + len + 0xFFF) & !0xFFF;

    // Capture cr3 AND a snapshot of file-backed VMA ranges that overlap
    // [start, end).  The snapshot is used below to suppress the per-page
    // zero-fill on file-backed pages, which (when a frame is also held by
    // the page cache) would silently corrupt the cache content shared with
    // other VmSpaces and future faulters — the W215 root cause.  See the
    // detailed rationale at the zero-fill site for the bug shape.
    //
    // Snapshot size is tiny in practice: a single madvise range typically
    // overlaps one VMA, occasionally two when straddling an arena boundary.
    let (cr3_opt, file_ranges) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let p = procs.iter().find(|p| p.pid == pid);
        let cr3 = p.and_then(|p| p.vm_space.as_ref()).map(|vs| vs.cr3);
        let mut ranges: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
        if let Some(vs) = p.and_then(|p| p.vm_space.as_ref()) {
            for vma in vs.areas.iter() {
                if !vma.overlaps(start, end - start) { continue; }
                if matches!(vma.backing, crate::mm::vma::VmBacking::File { .. }) {
                    ranges.push((vma.base, vma.end()));
                }
            }
        }
        (cr3, ranges)
    };
    let cr3 = match cr3_opt { Some(c) => c, None => return 0 };
    // Closure: O(file_ranges.len()) per page, where len is typically 0-2.
    let is_file_backed = |page: u64| -> bool {
        file_ranges.iter().any(|&(b, e)| page >= b && page < e)
    };

    // W216 H_5j-B: MADV_DONTNEED clears PTEs and frees frames; the area list
    // itself is not mutated, but the PFH install loop must abort if it has
    // any in-flight install for the same address space (otherwise it could
    // map a stale `pages_to_map[i]` whose underlying frame we just freed).
    crate::mm::vma::bump_generation_for_cr3(cr3);

    // Acquire the per-address-space read lock for the full clear→shootdown→free
    // sequence.  This serialises against any concurrent `clone_for_fork` that
    // holds the write side of the same mm_sem while walking the PML4.  Without
    // this guard a racing `clone_for_fork` on another CPU can observe and
    // resurrect PTEs that we are in the middle of clearing, re-inserting a
    // frame reference just before we return the frame to the PMM — the same
    // W215 aliasing race the PR #222 fix targets.
    //
    // The lock is held across ALL batches (the entire while-page-<-end loop)
    // so the protection gap between batches is also closed.  A single hoisted
    // acquisition is cheaper than re-acquiring per-batch and matches the shape
    // used by `unmap_and_free_range_in` in mm/vmm.rs.
    //
    // `mm_sem_for_cr3` returns `None` for kernel threads and AP bootstrap
    // contexts that have no registered VmSpace; those take the unlocked path
    // (no user page tables to protect).
    let _mm_guard = crate::mm::vma::mm_sem_for_cr3(cr3);
    let _mm_read  = _mm_guard.as_ref().map(|s| s.read());

    // SMP ordering invariant (Intel SDM Vol. 3A §4.10.5): PTEs must be cleared
    // and a synchronous TLB shootdown must complete on all CPUs BEFORE physical
    // frames are returned to the PMM.  Freeing a frame before the shootdown
    // creates a window where a sibling user-mode thread's stale TLB entry still
    // maps the freed frame; if the kernel allocates that frame in the meantime,
    // the sibling thread reads kernel data through the stale mapping.
    //
    // Three-pass approach:
    //   Pass 1 — zero and clear PTEs, collect physical addresses to free.
    //   Pass 2 — synchronous shootdown (IPI + ack) across all CPUs.
    //   Pass 3 — return frames to the PMM (safe after pass 2 completes).
    //
    // The batch buffer mirrors the BATCH constant in unmap_and_free_range_in
    // (mm/vmm.rs, PR #397).  At BATCH = 128, `to_free = [0u64; BATCH]`
    // consumes 1024 bytes of kernel stack.  The previous value of 1024 (8192
    // bytes) could overflow the 4 KiB emergency-fallback kstack when layered
    // on top of the madvise(2) entry path plus PTE walk, refcount decrement,
    // TLB shootdown, and PMM free.  The outer while-loop already handles
    // continuation across multiple batches, so this is a tuning change only:
    // no caller observes the batch boundary.
    //
    // Cite: madvise(2) (POSIX.1-2017); Intel SDM Vol. 3A §4.10.4-5.
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    const BATCH: usize = 128;

    let mut page = start;
    let mut any_unmap = false;

    while page < end {
        // --- Pass 1: zero backing storage, clear PTEs, collect to_free. ---
        let batch_start = page;
        let mut to_free = [0u64; BATCH];
        let mut n = 0usize;

        while page < end && n < BATCH {
            let pte = crate::mm::vmm::read_pte(cr3, page);
            if pte & 1 != 0 {
                let phys = pte & 0x000F_FFFF_FFFF_F000;
                // Zero the backing storage on anonymous pages only.  Per POSIX
                // madvise(2), MADV_DONTNEED on an anonymous region must cause
                // subsequent reads to return zeros, which the kernel achieves
                // here by zeroing the frame in place before the deferred-free.
                //
                // For file-backed VMAs the frame is typically co-owned by the
                // page cache (the cache holds rc=1, this PTE holds rc=1, so a
                // page_ref_dec returns new_rc=1 and the frame stays alive).
                // An unconditional zero-fill in that case clobbers the cache
                // content shared with every other VmSpace that holds — or will
                // hold — a PTE to the same `(mount_idx, inode, page_offset)`.
                // The next cache-hit faulter then maps in a frame whose
                // contents are zero, and pid 1's instruction fetch from the
                // shared libxul .text page reads zero bytes → SIGSEGV/#UD
                // with RIP bytes all-zero (the W215 fingerprint).  POSIX is
                // satisfied for file-backed ranges by clearing the PTE alone:
                // the next access re-faults via `cache::lookup_and_acquire`
                // and sees the authoritative file content.
                if !is_file_backed(page) {
                    unsafe {
                        core::ptr::write_bytes(
                            (PHYS_OFF + phys) as *mut u8,
                            0,
                            crate::mm::pmm::PAGE_SIZE,
                        );
                    }
                } else {
                    // Telemetry: count zero-fills suppressed by the file-backed
                    // guard.  A non-zero count after a clean Firefox boot
                    // confirms the W215 corruption path is being avoided in
                    // practice; a zero count under the same workload would
                    // mean the guard is dead code (e.g. file-backed regions
                    // never receiving MADV_DONTNEED) and the actual writer is
                    // elsewhere.
                    #[cfg(feature = "firefox-test-core")]
                    MADV_ZERO_SUPPRESSED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                // Clear the PTE.  Do NOT free the frame yet.
                crate::mm::vmm::write_pte(cr3, page, 0);
                any_unmap = true;

                // Atomic decrement (W198 / W190-H_G fix).  Pre-fix code
                // performed a non-atomic `page_ref_count` followed by
                // `page_ref_set(phys, 0)`, which silently wiped any
                // concurrent `page_ref_inc` from the readahead path or
                // a sibling `clone_for_fork` — driving the new count to
                // zero, freeing the frame, and creating an aliasing path
                // for the sibling whose still-installed PTE pointed at
                // the recycled frame.
                //
                // `page_ref_dec` returns the new count atomically
                // (fetch_sub).  Collect for deferred free iff it reaches
                // zero; otherwise the frame is still referenced (CoW
                // sibling, page cache) and the dec already accounts for
                // this PTE's released reference.
                //
                // Cite: Intel SDM Vol. 3A §4.10.5 (TLB consistency);
                // POSIX madvise(2) MADV_DONTNEED — the kernel may free
                // the pages but must do so without violating concurrent
                // mapping invariants.
                let new_rc = crate::mm::refcount::page_ref_dec(phys);
                if new_rc == 0 {
                    to_free[n] = phys;
                    n += 1;
                }
            }
            page += crate::mm::pmm::PAGE_SIZE as u64;
        }
        let batch_end = page;

        if any_unmap && batch_end > batch_start {
            // --- Pass 2: synchronous shootdown. ---
            // On return every CPU has evicted TLB entries for [batch_start, batch_end).
            let shootdown_clean =
                crate::mm::tlb::shootdown_range(cr3, batch_start, batch_end);

            // --- Pass 3: free frames now that no stale TLB entries remain. ---
            // Route through quarantine if the shootdown did not complete
            // cleanly (see unmap_and_free_range_in for the full rationale).
            for i in 0..n {
                if shootdown_clean {
                    crate::mm::pmm::free_page(to_free[i]);
                } else {
                    crate::mm::tlb::quarantine_free(to_free[i]);
                }
            }
        }
    }
    0
}

/// mremap(old_addr, old_size, new_size, flags, [new_addr])
///
/// Flags: MREMAP_MAYMOVE (1) — allowed to move mapping; MREMAP_FIXED (2) — use new_addr.
/// Returns the new mapping address on success, -errno on failure.
fn sys_mremap(old_addr: u64, old_size: u64, new_size: u64, flags: u64, new_addr: u64) -> i64 {
    use crate::mm::vma::{MAP_ANONYMOUS, MAP_FIXED};
    if new_size == 0 { return -22; } // EINVAL
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED:   u64 = 2;
    // MAP_FIXED_NOREPLACE (Linux 4.17+) — non-destructive fixed placement:
    // sys_mmap returns EEXIST (-17) instead of clobbering an existing VMA.
    // The in-place mremap grow MUST be non-destructive: per mremap(2), if the
    // region just past the old mapping is not free the in-place expansion
    // fails (and MREMAP_MAYMOVE then relocates) — it must NEVER overwrite an
    // adjacent mapping.  Using plain MAP_FIXED here corrupted whatever sat at
    // `old_addr+old_size`; when that was the top initial-stack page (argc/argv
    // per System V x86-64 psABI §3.4.1) it erased the command line, surfacing
    // as the upstream `argv[1]==NULL` crash.  Ref: man7 mremap(2), mmap(2)
    // (MAP_FIXED_NOREPLACE).
    const MAP_FIXED_NOREPLACE: u32 = 0x0010_0000;

    // Shrink: munmap the tail and return the same address.
    if new_size <= old_size {
        if new_size < old_size {
            let _ = crate::syscall::sys_munmap(old_addr + new_size, old_size - new_size);
        }
        return old_addr as i64;
    }

    // Grow — first try in-place extension.
    let ext_size = new_size - old_size;
    let ext_addr = old_addr + old_size;

    if flags & MREMAP_FIXED == 0 {
        // Attempt in-place: NON-DESTRUCTIVE fixed placement at the adjacent
        // address.  MAP_FIXED_NOREPLACE returns EEXIST (-17) if that range is
        // already mapped, so an occupied neighbour (e.g. the initial stack)
        // is left intact and we fall through to the move path below — exactly
        // the mremap(2) contract.  (Previously this used plain MAP_FIXED,
        // which clobbered the neighbour.)
        let r = crate::syscall::sys_mmap(ext_addr, ext_size, 0x3 /*PROT_READ|PROT_WRITE*/,
            MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, u64::MAX, 0);
        if r == ext_addr as i64 {
            return old_addr as i64; // grown in place (range was free)
        }
        // In-place failed (range occupied → EEXIST, or other error); move if allowed.
        if flags & MREMAP_MAYMOVE != 0 {
            let dest = crate::syscall::sys_mmap(0, new_size, 0x3, MAP_ANONYMOUS, u64::MAX, 0);
            if dest < 0 { return -12; } // ENOMEM
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::ptr::copy_nonoverlapping(
                    old_addr as *const u8, dest as *mut u8, old_size as usize);
            }
            let _ = crate::syscall::sys_munmap(old_addr, old_size);
            return dest;
        }
        -12 // ENOMEM — cannot grow in-place, move not allowed
    } else {
        // MREMAP_FIXED: must place at new_addr exactly.
        let dest = crate::syscall::sys_mmap(new_addr, new_size, 0x3,
            MAP_ANONYMOUS | MAP_FIXED, u64::MAX, 0);
        if dest < 0 { return dest; }
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::copy_nonoverlapping(
                old_addr as *const u8, dest as *mut u8, old_size.min(new_size) as usize);
        }
        let _ = crate::syscall::sys_munmap(old_addr, old_size);
        dest
    }
}

/// Linux read(fd, buf, count) — same semantics as AstryxOS read.
pub fn sys_read_linux(fd: u64, buf: u64, count: u64) -> i64 {
    let buf_ptr = buf as *mut u8;
    let count = count as usize;
    let pid = crate::proc::current_pid_lockless();

    // ── Special fd types take priority over the fd-number shortcuts ─────────
    // Must check these BEFORE the `fd == 0` stdin branch because kernel tests
    // and user processes may allocate eventfd/pipe/socket at fd 0.
    if crate::syscall::is_pipe_fd(pid, fd as usize) {
        let pipe_id = crate::syscall::get_pipe_id(pid, fd as usize);
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
        // Per `man 7 pipe` and `man 2 read`: a read on an empty pipe with the
        // write end still open blocks until data arrives (or a signal fires)
        // unless O_NONBLOCK is set.  EOF (write end closed) returns 0.  Pre-
        // fix this branch returned `Some(0)` immediately, leaving callers to
        // busy-spin via repeated read+poll cycles in user space.
        let nonblock = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid)
                .and_then(|p| p.file_descriptors.get(fd as usize).and_then(|f| f.as_ref()))
                .map(|f| (f.flags & 0x0800) != 0)
                .unwrap_or(false)
        };
        loop {
            match crate::ipc::pipe::pipe_read(pipe_id, buf) {
                None => return -9, // EBADF — pipe vanished (both ends closed).
                Some(n) if n > 0 => {
                    // The drain freed `n` bytes of ring-buffer space.  Per
                    // `man 7 pipe`, a writer that parked on a full (or
                    // insufficiently-roomed) buffer must be woken so it can
                    // re-evaluate and deposit.  Without this wake a writer
                    // parked via `wait_writable(.., u64::MAX)` never re-Readies
                    // (the scheduler excludes `u64::MAX` deadlines from the
                    // timer-wake scan) and deadlocks forever.  `pipe_read`
                    // dropped `PIPE_TABLE` before returning, so this wake takes
                    // the wait-list locks with no pipe lock held (lock order
                    // PIPE_WRITE_WAITERS -> THREAD_TABLE, no nesting against
                    // PIPE_TABLE).  The woken writer re-checks `space >= need`
                    // under the wait-list lock, so a drain that frees less than
                    // it needs re-parks it cleanly instead of wake-spinning.
                    crate::ipc::pipe::wake_writers_all(pipe_id);
                    return n as i64;
                }
                Some(_) => {
                    // 0 bytes returned: either EOF or empty-but-open.
                    if crate::ipc::pipe::pipe_is_eof(pipe_id) {
                        return 0; // EOF — peer closed the write end.
                    }
                    if nonblock {
                        return -11; // EAGAIN
                    }
                    if signal_pending(pid) {
                        return -4; // EINTR
                    }
                    // Park the caller atomically against pipe_write's wake.
                    let tid = crate::proc::current_tid();
                    match crate::ipc::pipe::wait_readable(pipe_id, u64::MAX) {
                        crate::ipc::pipe::WaitOutcome::Ready => continue,
                        crate::ipc::pipe::WaitOutcome::Gone  => return -9, // EBADF
                        crate::ipc::pipe::WaitOutcome::Enqueued => {
                            crate::sched::schedule();
                            // Cleanup any stale entry (e.g. timeout path) so
                            // we never leak a dead waiter on the per-pipe
                            // wait list.
                            crate::ipc::pipe::waiter_cleanup_reader(pipe_id, tid);
                        }
                    }
                }
            }
        }
    } else if crate::syscall::is_unix_socket_fd(pid, fd as usize) {
        let unix_id = crate::syscall::get_unix_socket_id(pid, fd as usize);
        // Per read(2) / unix(7): read on a blocking AF_UNIX socket (no
        // O_NONBLOCK) must block until a message is available; read(2) has no
        // flags argument, so blocking is governed solely by O_NONBLOCK.  Park
        // (bounded) until readable; non-blocking fds skip the wait and the
        // single drain below yields EAGAIN-on-empty unchanged.
        let blocking = !fd_is_nonblocking(pid, fd as usize);
        if let Err(e) = unix_recv_block_wait(unix_id, pid, blocking) {
            return e;
        }
        let avail = crate::net::unix::bytes_available(unix_id);
        let buf_sl = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
        let ret = crate::net::unix::read(unix_id, buf_sl);
        #[cfg(feature = "firefox-test-core")]
        if pid >= 1 {
            crate::serial_println!("[XSOCK] read fd={} uid={} want={} avail={} got={}",
                fd, unix_id, count, avail, ret);
        }
        return ret;
    } else if crate::syscall::is_socket_fd(pid, fd as usize) {
        let socket_id = crate::syscall::get_socket_id(pid, fd as usize);
        // Per read(2) / recv(2) / IEEE 1003.1: an empty receive on a
        // non-blocking socket is -1/EAGAIN; an orderly peer shutdown is a
        // 0-byte EOF.  The status-aware recv keeps the two apart so a polled
        // reader does not mistake an empty queue for EOF and re-read in a
        // busy loop (mirrors the pipe path above, which already separates
        // EOF from would-block).
        // Bounded by the read(2) buffer: excess stream bytes remain queued
        // for the next read (IEEE 1003.1 §recv).
        return match crate::net::socket::socket_recv_status(socket_id, count) {
            Ok(crate::net::socket::RecvOutcome::Data(data)) => {
                let n = data.len().min(count);
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, n);
                }
                n as i64
            }
            Ok(crate::net::socket::RecvOutcome::Eof) => 0,
            Ok(crate::net::socket::RecvOutcome::WouldBlock) => -11, // EAGAIN
            Err(_) => -11, // EAGAIN
        };
    } else if crate::syscall::is_eventfd_fd(pid, fd as usize) {
        if count < 8 { return -22; } // EINVAL
        let efd_id = crate::syscall::get_eventfd_id(pid, fd as usize);
        // Per `man 2 eventfd`: a read of zero counter blocks until non-zero,
        // unless the fd is non-blocking (set via EFD_NONBLOCK at creation or
        // O_NONBLOCK via fcntl(F_SETFL)).  Both flag sources flow through
        // the per-fd `flags` field and the eventfd entry's creation flags.
        let nonblock = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid)
                .and_then(|p| p.file_descriptors.get(fd as usize).and_then(|f| f.as_ref()))
                .map(|f| (f.flags & 0x0800) != 0)
                .unwrap_or(false)
        } || crate::ipc::eventfd::is_efd_nonblock(efd_id);
        loop {
            match crate::ipc::eventfd::try_read(efd_id) {
                Ok(val) => {
                    let bytes = val.to_le_bytes();
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, 8);
                    }
                    return 8;
                }
                Err(-11) if nonblock => return -11, // EAGAIN
                Err(-11) => {
                    // Atomic check-then-park against the per-eventfd wait
                    // list.  Replaces the prior `sleep_ticks(1)` busy-poll
                    // (10 ms latency, full CPU budget) with a real block
                    // that wakes promptly when `eventfd::write` posts.
                    if signal_pending(pid) { return -4; } // EINTR
                    let tid = crate::proc::current_tid();
                    match crate::ipc::eventfd::wait_readable(efd_id, u64::MAX) {
                        crate::ipc::eventfd::WaitOutcome::Ready => continue,
                        crate::ipc::eventfd::WaitOutcome::Gone  => return -9, // EBADF
                        crate::ipc::eventfd::WaitOutcome::Enqueued => {
                            crate::sched::schedule();
                            crate::ipc::eventfd::waiter_cleanup(efd_id, tid);
                        }
                    }
                }
                Err(e) => return e,
            }
        }
    } else if crate::syscall::is_timerfd_fd(pid, fd as usize) {
        if count < 8 { return -22; } // EINVAL
        let tfd_id = crate::syscall::get_timerfd_id(pid, fd as usize);
        return match crate::ipc::timerfd::read(tfd_id) {
            Ok(val) => {
                let bytes = val.to_le_bytes();
                unsafe {
                    let _g = crate::arch::x86_64::smap::UserGuard::new();
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_ptr, 8);
                }
                8
            }
            Err(e) => e,
        };
    } else if crate::syscall::is_signalfd_fd(pid, fd as usize) {
        let sfd_id = crate::syscall::get_signalfd_id(pid, fd as usize);
        return match crate::ipc::signalfd::read(sfd_id, buf_ptr, count) {
            Ok(n) => n as i64,
            Err(e) => e,
        };
    } else if crate::syscall::is_inotify_fd(pid, fd as usize) {
        let inotify_id = crate::syscall::get_inotify_id(pid, fd as usize);
        return match crate::ipc::inotify::read(inotify_id, buf_ptr, count) {
            Ok(n) => n as i64,
            Err(e) => e,
        };
    }

    // ── VFS file descriptors (covers ALL fds including 0/1/2) ──────────────
    // Try VFS first; if fd 0 has no VFS file open (BadFd), fall through to TTY.
    //
    // B-1 file-buf witness: snapshot the FILE struct's `buf`/`buf_size`
    // doublet (musl 1.2.5 layout, FILE at page-offset 0x10 → fields at
    // page-offset 0x68/0x70) before and after the VFS read so any
    // kernel-side write that lands on the FILE struct during the
    // syscall is named in the serial log.  Diagnostic-only; the
    // module compiles to empty no-op stubs in default builds.  See
    // `mm::file_buf_witness` and the B-1 gate-ownership verdict
    // (`memchr(rcx=NULL, '\n', 89)` from `fgets`).
    let __fbw_snap = crate::mm::file_buf_witness::pre_read(
        pid as u64, fd, buf as u64);
    match crate::vfs::fd_read(pid, fd as usize, buf_ptr, count) {
        Ok(n) => {
            crate::mm::file_buf_witness::post_read(__fbw_snap, n as i64);
            #[cfg(feature = "firefox-test-core")]
            {
                // Look up the fd's open_path to decide whether to peek.  We
                // do this AFTER the read so we see the actual returned bytes.
                // Only peek at synthetic filesystems; regular-disk reads are
                // high-volume and their content is uninteresting for the
                // decision-making path.
                // Snapshot the fd's open_path under PROCESS_TABLE, then drop
                // it explicitly before any ring::* call. The ring uses its own
                // RINGS lock; mixing the two acquisition orders across the
                // dispatch table would create an ABBA hazard (RINGS held by
                // begin() vs PROCESS_TABLE held by mmap dispatch). Keeping
                // the path snapshot strictly lock-disjoint avoids that hazard
                // even as future code is added between the two operations.
                let path = {
                    let procs = crate::proc::PROCESS_TABLE.lock();
                    let p = procs.iter().find(|p| p.pid == pid)
                        .and_then(|p| p.file_descriptors.get(fd as usize))
                        .and_then(|f| f.as_ref())
                        .map(|f| f.open_path.clone())
                        .unwrap_or_default();
                    drop(procs);
                    p
                };
                if !path.is_empty() && crate::syscall::ring::is_synthetic_path(&path) {
                    // Snapshot up to READ_BYTES (256) into a Vec we can feed
                    // to the ring-entry helper and to the inline log line.
                    let take = n.min(crate::syscall::ring::READ_BYTES);
                    // SMAP-bracketed snapshot — the buf_ptr derefs target
                    // user memory.  Allocate the Vec upfront (outside the
                    // guard) so the AC=1 region only spans the byte reads.
                    let mut staging = [0u8; crate::syscall::ring::READ_BYTES];
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        for i in 0..take {
                            staging[i] = *buf_ptr.add(i);
                        }
                    }
                    let snap: alloc::vec::Vec<u8> = staging[..take].to_vec();
                    let idx = crate::subsys::linux::syscall_ring::current_entry();
                    crate::syscall::ring::set_read_bytes(pid, idx, &snap);
                    crate::syscall::ring::log_synthetic_read(
                        fd, &path, n as i64, &snap);
                }
            }
            return n as i64;
        }
        Err(crate::vfs::VfsError::BadFd) if fd == 0 => { /* fall through to TTY stdin */ }
        Err(_) if fd == 0 => { /* fall through to TTY stdin */ }
        Err(e) => {
            // Map VfsError to its POSIX errno value (the enum discriminants
            // are the POSIX numbers by design — see `vfs::VfsError`).  This
            // distinguishes EIO from EBADF so callers like glibc's
            // dynamic-linker `read()` retry path can react appropriately;
            // see W160 (virtio-blk EBADF on transient I/O timeout, which
            // previously collapsed to -9 here and tricked ld-linux into
            // reporting an invalid ELF header).
            return -(e as i64);
        }
    }

    // fd 0 with no VFS file → stdin via TTY line discipline.
    // Limit spin-wait to 500 iterations (~5ms at 100Hz timer) so that a
    // user process calling read(0, …) in a loop does not stall the entire
    // system for seconds waiting for keyboard input that will never arrive
    // (especially in headless test mode).
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, count) };
    let mut attempts = 0u32;
    loop {
        {
            let mut tty = crate::drivers::tty::TTY0.lock();
            crate::drivers::tty::pump_keyboard(&mut tty);
            let n = tty.read(buf, count);
            if n > 0 {
                return n as i64;
            }
        }
        attempts += 1;
        if attempts > 500 {
            return 0;
        }
        core::hint::spin_loop();
    }
}

// ── Render-lifecycle MILESTONE markers (low-frequency, DEFAULT-ON) ──────────
//
// Distinct from the `[FF/stderr]`/`[FF/write]` per-write firehose above (which
// is gated on the `*-trace` features and transcribes EVERY tracked write — one
// PIO VM-exit per byte, ~78% of a full boot log). These milestone markers are
// the OPPOSITE: a tiny curated substring set covering the headless-screenshot
// render lifecycle, each emitted EXACTLY ONCE per boot (first-arrival), so the
// total cost is a handful of serial lines for the whole run — not a firehose.
//
// They exist so the deep render gates are visible on the fast default profile
// (`firefox-test-core`, diagnostic serial OFF) without re-enabling the firehose:
// the serial monitor and perf phase taxonomy detect `screenshot-actors`,
// `drawSnapshot`, etc. from these `[GATE] <label>` lines instead of from the
// now-gated-off `[FF/write]` mirror.
//
// Each curated substring maps to one bit of `MILESTONE_SEEN`; once a bit is set
// the marker never re-emits, so a matching string appearing thousands of times
// in FF's IPDL traffic still produces a single line. The earlier bring-up gates
// are emitted elsewhere: content-process spawn from the exec path
// (`[GATE] content-procs`, next to the `[EXEC] …-isForBrowser` argv line) and
// libxul load from the open path (`[GATE] libxul`, because the per-open
// `[FF/open]` mirror is trace-gated). So this write-payload set only needs the
// render-stage substrings that have no other default-on signal.
//
// (label, substring) — order is the bit index; keep ≤32 entries (u32 mask).
#[cfg(feature = "firefox-test-core")]
const MILESTONE_MARKERS: &[(&str, &[u8])] = &[
    // screenshot-actors stage — the IPDL screenshot query/parent actors. These
    // protocol-actor names are specific to the headless-screenshot path and do
    // not appear in ordinary page content.
    ("screenshot-actors", b"getDimensions"),
    ("screenshot-actors", b"ScreenshotParent"),
    ("screenshot-actors", b"sendQuery"),
    // drawSnapshot / cross-process paint stage — the actual composite + draw.
    // `drawSnapshot` and `CrossProcessPaint` are render-API-specific symbols.
    ("drawSnapshot",      b"drawSnapshot"),
    ("drawSnapshot",      b"CrossProcessPaint"),
    // NOTE: the FINAL screenshot-PNG write is intentionally NOT detected here by
    // the raw `\x89PNG` magic — Firefox writes many internal PNGs (favicons,
    // theme/UI assets) whose payloads also start with that signature, so a
    // magic-based `[GATE] PNG` would false-positive long before the real
    // screenshot. The authoritative, single-per-run PNG-write signal is the FF
    // supervisor's functional `[FFTEST] /tmp/out.png present` /
    // `[FF-OUT-PNG:… sig_ok=true …]` lines (default-on on firefox-test-core),
    // which the gate consumers key on for the PNG gate.
];

/// First-arrival bitmask for [`MILESTONE_MARKERS`]: bit `i` set ⇒ marker `i`
/// has already emitted its `[GATE]` line. Lockless, default-relaxed — a benign
/// double-emit under a 2-CPU race is harmless (the monitor takes first-arrival),
/// and the common case (bit already set) is a single atomic load with no store.
#[cfg(feature = "firefox-test-core")]
static MILESTONE_SEEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Scan a write payload for the curated render-lifecycle milestone substrings
/// and emit one `[GATE] <label>` line the FIRST time each is seen this boot.
///
/// Called from the tracked-write path on the DEFAULT (core) profile. Cheap: a
/// bounded substring search over an already-snapshotted buffer, skipped entirely
/// once every milestone bit is set. Never allocates, never takes a lock.
#[cfg(feature = "firefox-test-core")]
#[inline]
fn emit_render_milestones(snapshot: &[u8]) {
    use core::sync::atomic::Ordering;
    let seen = MILESTONE_SEEN.load(Ordering::Relaxed);
    // Fast exit once every curated marker has fired (the steady state for the
    // vast majority of a boot's writes).
    let all_mask: u32 = (1u32 << MILESTONE_MARKERS.len()) - 1;
    if seen == all_mask {
        return;
    }
    for (i, (label, needle)) in MILESTONE_MARKERS.iter().enumerate() {
        let bit = 1u32 << i;
        if seen & bit != 0 {
            continue; // already emitted this marker
        }
        if !slice_contains(snapshot, needle) {
            continue;
        }
        // First arrival — claim the bit and emit exactly one milestone line.
        // fetch_or returns the PRE-update value; only the CPU that observed the
        // bit clear emits, so a concurrent partner cannot double-print.
        let prev = MILESTONE_SEEN.fetch_or(bit, Ordering::Relaxed);
        if prev & bit == 0 {
            crate::serial_println!("[GATE] {}", label);
        }
    }
}

/// Bounded substring search (`haystack.windows(needle.len()).any(== needle)`),
/// kept allocation-free for the milestone hot path.
#[cfg(feature = "firefox-test-core")]
#[inline]
fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Linux write(fd, buf, count) — same semantics as AstryxOS write.
pub fn sys_write_linux(fd: u64, buf: u64, count: u64) -> i64 {
    let buf_ptr = buf as *const u8;
    let count = count as usize;

    if count == 0 { return 0; }

    // Render-lifecycle MILESTONE markers (low-frequency, DEFAULT-ON on the
    // Firefox bring-up profile). Scans the write payload for a curated set of
    // render-stage substrings and emits ONE `[GATE] <label>` line the first
    // time each is seen — a handful of lines for the whole boot, NOT the
    // per-write `[FF/write]` firehose below (which stays *-trace-gated). This
    // makes the deep render gates visible on the fast `firefox-test-core` boot
    // (where the firehose is OFF) without paying the firehose cost.
    //
    // Gated on `firefox-test-core` (present in every FF profile incl. the full
    // `firefox-test`/`*-trace` superset) so plain `test-mode` / production
    // builds are byte-identical. The snapshot is bounded (512 B) and skipped
    // once every milestone bit is set, so the steady-state cost is one atomic
    // load per tracked write.
    #[cfg(feature = "firefox-test-core")]
    {
        let mpid = crate::proc::current_pid_lockless();
        if (mpid == 1 || crate::syscall::ring::is_tracked(mpid))
            && MILESTONE_SEEN.load(core::sync::atomic::Ordering::Relaxed)
                != (1u32 << MILESTONE_MARKERS.len()) - 1
        {
            let take = count.min(512);
            // SMAP-bracketed snapshot of the user buffer — the milestone scan
            // reads kernel memory only (Intel SDM Vol. 3A §4.6.1).
            let snap: alloc::vec::Vec<u8> = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::slice::from_raw_parts(buf_ptr, take).to_vec()
            };
            emit_render_milestones(&snap);
        }
    }

    // CHILD-process stderr mirror ([FF/stderr-child]) — core-gated, cheap.
    // Firefox CHILD processes (content/socket/rdd) write almost nothing to
    // stderr (a handful of NSPR module-log lines per process), but when one
    // aborts its init the reason is printed there.  pid 1 is the heavy
    // stderr writer, so excluding it keeps this within a few KB per boot —
    // affordable on the fast profile where the full *-trace mirror is off.
    // Skipped on trace builds (the full mirror below already covers it).
    #[cfg(all(feature = "firefox-test-core", not(feature = "firefox-test-trace")))]
    {
        // Per-boot line budget: a full stdout pipe makes musl stdio retry
        // the same write(2) forever (see the Gate-1 pipe-blocking finding);
        // without a cap that retry-spin floods serial with one mirrored
        // line per attempt.
        use core::sync::atomic::{AtomicU32, Ordering};
        static STDERR_CHILD_LINES: AtomicU32 = AtomicU32::new(0);
        let cpid = crate::proc::current_pid_lockless();
        if fd == 2 && cpid > 1 && count >= 4
            && STDERR_CHILD_LINES.fetch_add(1, Ordering::Relaxed) < 192
        {
            let take = count.min(256);
            let snap: alloc::vec::Vec<u8> = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::slice::from_raw_parts(buf_ptr, take).to_vec()
            };
            let mut buf = alloc::string::String::with_capacity(take + 16);
            for &b in &snap {
                match b {
                    b'\n' => buf.push_str("\\n"),
                    0x20..=0x7e => buf.push(b as char),
                    _ => buf.push('.'),
                }
            }
            if count > 256 { buf.push_str("..."); }
            crate::serial_println!(
                "[FF/stderr-child] pid={} bytes={} body=\"{}\"", cpid, count, buf);
        }
    }

    // Diagnostic stdout/stderr mirror ([FF/stderr] / [FF/write] / [FF/write-fd]).
    // This is the single largest serial source on a Firefox boot (~78% of a
    // ~45 MB log) and has no correctness role — it transcribes every tracked
    // write(2) to COM1, one PIO VM-exit per byte under KVM.  Gated on the
    // *-trace features so the functional `firefox-test-core` / plain `test-mode`
    // builds run identically without the spew.  `ff-stderr-mirror` enables
    // JUST this mirror (no other firehose) for near-perf-timing capture of a
    // child's abort/assertion text — see kernel/Cargo.toml.
    #[cfg(any(feature = "firefox-test-trace", feature = "test-mode-trace",
              feature = "ff-stderr-mirror"))]
    {
        let pid = crate::proc::current_pid_lockless();
        if pid == 1 || crate::syscall::ring::is_tracked(pid) {
            // SMAP-bracketed snapshot of the user buffer into a kernel
            // Vec so the logging chatter below runs on kernel memory.
            // The snapshot is capped at 512 bytes; everything we log
            // (escape-printer, hex dump) reads from `snapshot` only.
            let snap_take = count.min(512);
            let snapshot: alloc::vec::Vec<u8> = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                core::slice::from_raw_parts(buf_ptr, snap_take).to_vec()
            };
            // Skip ultra-short non-printable bursts (e.g. the 1-byte `\n`
            // ping-pongs some stdio buffers emit) unless clearly human-visible
            // output.  ASCII-printable / whitespace passes through.
            let should_log = count >= 4 || snapshot.iter().all(|&b| {
                b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b)
            });
            if should_log {
                let truncated = count > 512;
                let mut buf = alloc::string::String::with_capacity(snap_take + 16);
                for &b in &snapshot {
                    match b {
                        b'\n' => buf.push_str("\\n"),
                        b'\r' => buf.push_str("\\r"),
                        b'\t' => buf.push_str("\\t"),
                        b'\\' => buf.push_str("\\\\"),
                        b'"'  => buf.push_str("\\\""),
                        0x20..=0x7e => buf.push(b as char),
                        _ => { let _ = core::fmt::Write::write_fmt(&mut buf, format_args!("\\x{:02x}", b)); }
                    }
                }
                if truncated { buf.push_str("..."); }
                let tag = if fd == 2 { "FF/stderr" } else { "FF/write" };
                crate::serial_fast_println!("[{}] pid={} fd={} bytes={} body=\"{}\"", tag, pid, fd, count, buf);
            }

            // Full-fd coverage: capture writes to fds OTHER than 0/1/2 so we
            // see any diagnostic chatter that was redirected to a log file,
            // syslog socket, etc.  Hex-encode the first 64 bytes — we don't
            // know the encoding so don't assume UTF-8.
            if fd > 2 {
                let take = count.min(64);
                let hex_src = &snapshot[..snapshot.len().min(take)];
                let mut hex = alloc::string::String::with_capacity(take * 2);
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for &b in hex_src {
                    hex.push(HEX[(b >> 4) as usize] as char);
                    hex.push(HEX[(b & 0xF) as usize] as char);
                }
                crate::serial_fast_println!(
                    "[FF/write-fd] pid={} fd={} len={} bytes={}",
                    pid, fd, count, hex
                );
            }
        }
    }

    // ── Special fd types take priority over the fd-number shortcuts ─────────
    // Must check these BEFORE the `fd == 1/2` stdout/stderr branch because
    // kernel tests and user processes may allocate pipe/socket/eventfd at fd 1.
    let pid = crate::proc::current_pid_lockless();

    // Decide once whether the destination is a kernel-internal fd type that
    // will hold the slice past the UserGuard scope (pipe/socket/unix/eventfd
    // queue the bytes into kernel buffers; UDP packetises into its own Vec;
    // TCP enqueues into the send window).  For all of these we must snapshot
    // the user buffer into a kernel Vec BEFORE invoking the downstream code,
    // otherwise the downstream's `extend_from_slice` / queue copy reads user
    // memory with AC=0 and faults under SMAP (Intel SDM Vol. 3A §4.6).
    //
    // The VFS fd_write path below threads the raw user pointer through into
    // its own STAC/CLAC-bracketed copy helpers, so we don't need to snapshot
    // for that case — keeping the zero-copy fast path intact.
    let is_pipe   = crate::syscall::is_pipe_fd(pid, fd as usize);
    let is_unix   = !is_pipe && crate::syscall::is_unix_socket_fd(pid, fd as usize);
    let is_inet   = !is_pipe && !is_unix && crate::syscall::is_socket_fd(pid, fd as usize);
    let is_evfd   = !is_pipe && !is_unix && !is_inet
                    && crate::syscall::is_eventfd_fd(pid, fd as usize);

    if is_pipe || is_unix || is_inet || is_evfd {
        // User-pointer check: required for real user-space callers to prevent
        // ring-0 from writing kernel memory on behalf of a user process (CWE-823).
        // Bypassed when called from dispatch_linux_kernel (KernelDispatchGuard),
        // where the caller deliberately passes kernel-resident buffers — the
        // test_runner pipe write/read path is the canonical example.
        if !crate::syscall::user_ptr_check_bypassed()
            && !crate::syscall::validate_user_ptr(buf as u64, count)
        {
            return -14; // EFAULT
        }
        // Snapshot the entire buffer to kernel memory.  For user-mode callers,
        // the SMAP bracket (STAC/CLAC) prevents the copy from trapping on a
        // user page with CR4.SMAP set.  For kernel-dispatch callers the bracket
        // is harmless — STAC on an already-kernel-readable address is a no-op.
        // Intel SDM Vol. 3A §4.6.1: SMAP only restricts supervisor accesses to
        // user-mode (non-supervisor) pages; kernel pages are always accessible.
        let snapshot: alloc::vec::Vec<u8> = unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::slice::from_raw_parts(buf_ptr, count).to_vec()
        };
        let data: &[u8] = &snapshot;

        if is_pipe {
            let pipe_id = crate::syscall::get_pipe_id(pid, fd as usize);
            return pipe_write_blocking(pid, fd as usize, pipe_id, data);
        }
        if is_unix {
            let unix_id = crate::syscall::get_unix_socket_id(pid, fd as usize);
            return crate::net::unix::write(unix_id, data);
        }
        if is_inet {
            let socket_id = crate::syscall::get_socket_id(pid, fd as usize);
            return match crate::net::socket::socket_send(socket_id, data) {
                Ok(n) => n as i64,
                Err("EPIPE") => -32, // EPIPE — caller did SHUT_WR
                Err(_) => -104, // ECONNRESET
            };
        }
        // is_evfd
        if count < 8 { return -22; } // EINVAL
        let efd_id = crate::syscall::get_eventfd_id(pid, fd as usize);
        let val_bytes: [u8; 8] = [
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ];
        let val = u64::from_le_bytes(val_bytes);
        return match crate::ipc::eventfd::write(efd_id, val) {
            Ok(()) => {
                // Per `man 2 eventfd`: a write that bumps the counter must
                // wake any reader parked on a zero counter (see the per-
                // eventfd wait list in `crate::ipc::eventfd`).
                crate::ipc::eventfd::wake_readers_all(efd_id);
                8
            }
            Err(e) => e,
        };
    }

    // ── VFS file descriptors (covers ALL fds including 0/1/2) ──────────────
    // Try VFS first; if fd 1/2 has no VFS file open (BadFd), fall through to TTY.
    match crate::vfs::fd_write(pid, fd as usize, buf_ptr, count) {
        Ok(n) => return n as i64,
        Err(_) if fd == 1 || fd == 2 => { /* fall through to TTY stdout/stderr */ }
        Err(_) => return -9, // EBADF for other fds
    }

    // fd 1/2 with no VFS file → TTY stdout/stderr.  Same SMAP discipline as
    // the special-fd paths above: TTY's write() reads every byte of the slice
    // into the line buffer, holding the read past the UserGuard would risk a
    // mismatched bracket.  Snapshot first.
    // Bypassed when called from dispatch_linux_kernel (KernelDispatchGuard):
    // kernel-test callers legitimately pass kernel-resident buffers.
    if !crate::syscall::user_ptr_check_bypassed()
        && !crate::syscall::validate_user_ptr(buf as u64, count)
    {
        return -14; // EFAULT
    }
    let tty_snap: alloc::vec::Vec<u8> = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::slice::from_raw_parts(buf_ptr, count).to_vec()
    };
    crate::drivers::tty::TTY0.lock().write(&tty_snap);
    count as i64
}

/// Blocking-aware pipe `write(2)`.
///
/// Implements the POSIX `write(2)` / `pipe(7)` contract that the prior
/// one-shot `pipe_write` violated (it deposited whatever fit and returned
/// immediately, so a full pipe yielded a no-progress `0` return and musl
/// stdio retried the same write forever — wedging a child on its first
/// stderr line once the peer stopped draining stdout):
///
///   * **Atomicity (`count <= PIPE_BUF`)** — the write is delivered all in
///     one piece or not at all.  On a blocking fd we park until `count`
///     contiguous bytes of space exist, then deposit them in a single
///     `PIPE_TABLE` critical section (`pipe::pipe_write_atomic`): the
///     space-check and the deposit are indivisible, so two concurrent
///     atomic writers can never both observe `space >= count` and publish
///     interleaved partial records.  A blocking fd NEVER returns a short
///     write for `count <= PIPE_BUF`.
///   * **Large writes (`count > PIPE_BUF`)** — may be split.  We write what
///     fits, wake readers, then block for more space and continue until all
///     `count` bytes are written (or a signal interrupts a write that has
///     already made partial progress, in which case the partial count is
///     returned per `write(2)`).
///   * **`O_NONBLOCK`** — if no progress can be made the call returns
///     `-EAGAIN`; for `count <= PIPE_BUF` "progress" means the whole write
///     fits (atomicity is preserved — no partial), for `count > PIPE_BUF`
///     any free space is partial progress.
///   * **No reader (`EPIPE`)** — if every read end is closed the write
///     fails with `-EPIPE`.  (SIGPIPE delivery is a separate, pre-existing
///     gap — see `man 2 write`; not raised here.)
///
/// Blocking reuses the existing per-pipe writer wait list
/// (`PIPE_WRITE_WAITERS`) via the needs-aware `pipe::wait_writable` — the
/// exact check-then-park primitive the reader path uses with
/// `pipe::wait_readable`.  We pass `need` = the contiguous free space this
/// write must see before retrying (`count` for an atomic write, `1` for a
/// large write), so a writer parked for room does NOT wake-spin when a
/// reader frees less than it needs.  No lock is held across `schedule()`:
/// `wait_writable` takes and drops `PIPE_TABLE`/`PIPE_WRITE_WAITERS`
/// internally and returns `Enqueued`; only then do we `schedule()`.  A
/// reader's drain calls `wake_writers_all` (the `read(2)` pipe arm of
/// `sys_read_linux` does so on every nonzero drain, as do the close-end
/// paths), which wakes us — and the `wait_writable` re-check under the
/// wait-list lock re-evaluates `space >= need`, closing the TOCTOU window
/// against a drain that races our own space probe (a drain freeing
/// `< need` re-parks us cleanly rather than consuming the wake and
/// spinning).
fn pipe_write_blocking(pid: u64, fd: usize, pipe_id: u64, data: &[u8]) -> i64 {
    use crate::ipc::pipe::{AtomicWrite, WaitOutcome};
    let count = data.len();
    // A zero-byte write to a pipe is a no-op that returns 0 (per write(2):
    // "If count is zero ... write() ... return[s] zero").  Don't wake or
    // block; just report success.
    if count == 0 {
        return 0;
    }
    let nonblock = fd_is_nonblocking(pid, fd);
    let atomic = count <= crate::ipc::pipe::PIPE_BUF;

    let mut total: usize = 0;
    loop {
        // EPIPE if the reader is gone (per write(2)).  Checked first so a
        // writer that filled the buffer and then lost its reader fails
        // rather than parking forever.  If we've already written some
        // bytes for a >PIPE_BUF write, POSIX still allows returning the
        // partial count; but EPIPE on a pipe with a vanished reader is the
        // dominant, expected error and matches Linux, so report it.
        if crate::ipc::pipe::pipe_reader_closed(pipe_id) {
            if total > 0 {
                return total as i64;
            }
            return -32; // EPIPE
        }

        // ── Atomic arm (count <= PIPE_BUF) ────────────────────────────────
        // The check-and-deposit happens under ONE PIPE_TABLE lock so the
        // record is published whole or not at all, never interleaved with a
        // concurrent atomic writer (man 7 pipe, PIPE_BUF).  `total` is
        // always 0 here — an atomic write makes no partial progress.
        if atomic {
            match crate::ipc::pipe::pipe_write_atomic(pipe_id, data) {
                AtomicWrite::Wrote => {
                    // Whole record landed — wake readers parked on an empty
                    // pipe (man 7 pipe) and report the full count.
                    crate::ipc::pipe::wake_readers_all(pipe_id);
                    return count as i64;
                }
                AtomicWrite::Gone => return -9, // EBADF — pipe vanished
                AtomicWrite::NoSpace => {
                    // Not enough contiguous room.  Fall through to the
                    // O_NONBLOCK / signal / park handling below with the
                    // needs-aware `need == count` park, so we sleep until a
                    // reader frees room for the WHOLE record rather than
                    // spinning on partial space.
                }
            }
        } else {
            // ── Large arm (count > PIPE_BUF) — partials allowed ───────────
            let space = crate::ipc::pipe::pipe_space(pipe_id);
            let remaining = count - total;
            let writable_now = space.min(remaining);
            if writable_now > 0 {
                let chunk = &data[total..total + writable_now];
                match crate::ipc::pipe::pipe_write(pipe_id, chunk) {
                    Some(n) => {
                        if n > 0 {
                            total += n;
                            // Wake readers parked on an empty pipe (man 7 pipe).
                            crate::ipc::pipe::wake_readers_all(pipe_id);
                        }
                        if total >= count {
                            return total as i64;
                        }
                        // More to write — loop to deposit the rest.
                        continue;
                    }
                    // Pipe vanished mid-write (both ends closed): EBADF if we
                    // never made progress, else the partial count.
                    None => {
                        if total > 0 { return total as i64; }
                        return -9; // EBADF
                    }
                }
            }
        }

        // No room to make progress this pass.
        if nonblock {
            // O_NONBLOCK: never block.  If nothing was written, EAGAIN; if a
            // >PIPE_BUF write already deposited some bytes, return the
            // partial count (man 2 write: a non-blocking partial write
            // returns the number of bytes written).
            if total > 0 { return total as i64; }
            return -11; // EAGAIN
        }

        // A signal that arrives before ANY data is written aborts with
        // EINTR; after partial progress on a large write, return the
        // partial count (man 7 signal restart semantics for slow devices).
        if signal_pending(pid) {
            if total > 0 { return total as i64; }
            return -4; // EINTR
        }

        // Park atomically against the reader's `wake_writers_all`, using a
        // needs-aware predicate so a writer does NOT wake-spin when a reader
        // frees less room than this write requires:
        //   * atomic write (count <= PIPE_BUF): need == count — park until
        //     the WHOLE record fits (a write into 0 < space < count makes no
        //     progress, so waking on any space would livelock at 100% CPU);
        //   * large write (count > PIPE_BUF): need == 1 — any free byte is
        //     forward progress, so wake as soon as room appears.
        // Lock order PIPE_WRITE_WAITERS -> PIPE_TABLE is taken and released
        // entirely inside `wait_writable`; we hold no pipe lock across the
        // `schedule()` below (the #476/#499/#500 hold-across-dispatch class
        // of deadlock cannot occur here).
        let need = if atomic { count } else { 1 };
        let tid = crate::proc::current_tid();
        match crate::ipc::pipe::wait_writable(pipe_id, need, u64::MAX) {
            // Enough room appeared (or the reader closed) between our check
            // and the wait-list re-check — retry the loop, which re-evaluates
            // reader-closed (EPIPE) and re-attempts the atomic/large deposit.
            WaitOutcome::Ready => continue,
            // Pipe id no longer exists — EBADF if no progress, else partial.
            WaitOutcome::Gone => {
                if total > 0 { return total as i64; }
                return -9; // EBADF
            }
            WaitOutcome::Enqueued => {
                crate::sched::schedule();
                // Drop any stale entry (timeout/interrupt path) so we never
                // leak a dead waiter on PIPE_WRITE_WAITERS.
                crate::ipc::pipe::waiter_cleanup_writer(pipe_id, tid);
            }
        }
    }
}

/// Linux open(pathname, flags, mode) — pathname is a C string.
pub fn sys_open_linux(pathname: u64, flags: u64, _mode: u64) -> i64 {
    // NOTE on pointer validation: the user-mode dispatch path applies
    // `user_path_ptr_ok(pathname)` in `dispatch_body` BEFORE this handler
    // is invoked (per CWE-823).  Internal kernel callers (`sys_open_test`,
    // `vfs::sys_open` glue, …) deliberately call this function with
    // kernel pointers and rely on `read_cstring_from_user` to NUL-walk
    // a kernel-resident string.  Adding a strict range check here would
    // break those legitimate kernel-internal call sites; the validation
    // belongs at the user/kernel boundary, not inside the handler.
    //
    // Snapshot the path up front so `[FF/open-ret]` can quote it even if
    // the path argument points into user memory that the handler later
    // re-reads. The inner impl re-decodes for its own logic.  Trace-gated to
    // match the emit below so the perf core boot pays neither the extra
    // user-string read nor the allocation.
    #[cfg(any(feature = "firefox-test-trace", feature = "test-mode-trace"))]
    let path_snapshot: alloc::string::String = {
        let bytes = read_cstring_from_user(pathname);
        alloc::string::String::from_utf8_lossy(&bytes).into_owned()
    };
    let ret = sys_open_linux_inner(pathname, flags, _mode);
    // Per-open(2) diagnostic mirror — high-frequency; gated to the trace
    // features so the perf core boot does not pay a serial line per open.
    #[cfg(any(feature = "firefox-test-trace", feature = "test-mode-trace"))]
    {
        let pid = crate::proc::current_pid_lockless();
        if pid == 1 || crate::syscall::ring::is_tracked(pid) {
            crate::serial_fast_println!(
                "[FF/open-ret] pid={} path={} ret={}",
                pid, path_snapshot, ret,
            );
        }
    }
    ret
}

fn sys_open_linux_inner(pathname: u64, flags: u64, _mode: u64) -> i64 {
    // O_TMPFILE (per open(2)) is encoded as 0x410000 (0x400000 | O_DIRECTORY).
    // The detection bit is 0x400000.  The flag asks the kernel to create an
    // unnamed inode under the given directory; we have no anonymous-inode
    // support yet, so report -EOPNOTSUPP.  glibc's mkstemp falls back to the
    // ordinary O_RDWR|O_CREAT|O_EXCL path which we already implement.
    const O_TMPFILE_BIT: u64 = 0x0040_0000;
    if flags & O_TMPFILE_BIT != 0 {
        return -95; // EOPNOTSUPP
    }

    let path_bytes = read_cstring_from_user(pathname);
    let path_raw = match core::str::from_utf8(&path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    let pid = crate::proc::current_pid_lockless();
    // Per open(2) (IEEE Std 1003.1-2017) and `man 7 path_resolution`:
    // "If the pathname given in pathname is relative, then it is interpreted
    //  relative to the directory referred to by the file descriptor dirfd."
    // For the legacy open(2) entry, the implicit dirfd is AT_FDCWD, i.e. the
    // process working directory.  `crate::vfs::resolve_path` is CWD-blind
    // (it treats every input as anchored at "/"), so resolve relative paths
    // here against `Process::cwd` BEFORE handing off to the special-path
    // matchers and the VFS open.  This matches the openat(AT_FDCWD, …)
    // handler below and the sys_stat_linux / sys_access pattern.
    //
    // Empty paths fall through unchanged so the downstream layers produce a
    // POSIX-compliant ENOENT (per open(2): "If pathname is an empty string,
    // open() shall return -1 with errno set to ENOENT.").
    let path_owned: alloc::string::String = if path_raw.is_empty() || path_raw.starts_with('/') {
        alloc::string::String::from(path_raw)
    } else {
        let cwd = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid)
                .map(|p| p.cwd.clone())
                .unwrap_or_else(|| alloc::string::String::from("/"))
        };
        if cwd.ends_with('/') {
            alloc::format!("{}{}", cwd, path_raw)
        } else {
            alloc::format!("{}/{}", cwd, path_raw)
        }
    };
    let path: &str = path_owned.as_str();
    // Per-open(2) path mirror — high-frequency diagnostic; trace-gated so the
    // perf core boot does not emit a serial line per open.
    #[cfg(any(feature = "firefox-test-trace", feature = "test-mode-trace"))]
    if pid == 1 || crate::syscall::ring::is_tracked(pid) {
        crate::serial_fast_println!("[FF/open] pid={} path={}", pid, path);
    }
    // libxul load MILESTONE (low-frequency, DEFAULT-ON). The per-open `[FF/open]`
    // mirror above is trace-gated, so on the fast `firefox-test-core` boot the
    // gate monitor has no default-on signal that the main shared library mapped.
    // Emit a single `[GATE] libxul` the first time libxul is opened by a tracked
    // process — one line per boot, not the per-open firehose.
    #[cfg(feature = "firefox-test-core")]
    {
        use core::sync::atomic::{AtomicBool, Ordering};
        static LIBXUL_GATE_SEEN: AtomicBool = AtomicBool::new(false);
        if (pid == 1 || crate::syscall::ring::is_tracked(pid))
            && path.ends_with("libxul.so")
            && !LIBXUL_GATE_SEEN.swap(true, Ordering::Relaxed)
        {
            crate::serial_println!("[GATE] libxul");
        }
    }
    // Attach the resolved path string to the pending ring entry so the ring
    // dump can show what each open() / openat() actually tried to open.
    #[cfg(feature = "firefox-test-core")]
    {
        let idx = crate::subsys::linux::syscall_ring::current_entry();
        crate::syscall::ring::set_path(pid, idx, path);
    }

    // Refresh /proc/self/maps with dynamic per-process VMA content before opening.
    if path == "/proc/self/maps" {
        refresh_proc_maps(pid);
    }
    // Refresh /proc/self/status with live PID, PPID, FDSize, VmRSS.
    if path == "/proc/self/status" {
        refresh_proc_status(pid);
    }

    // ── /dev/dsp — OSS-compatible audio output via AC97 ─────────────────
    // Return ENODEV immediately if the AC97 controller was not probed so
    // callers can fall back gracefully rather than receiving a stale fd that
    // silently discards all writes.
    if path == "/dev/dsp" {
        if !crate::drivers::ac97::is_available() {
            return -19; // ENODEV
        }
        match crate::vfs::open(pid, path, flags as u32) {
            Ok(fd_num) => {
                // Tag the fd with bit 23 so fd_write routes to the AC97 ring.
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = p.file_descriptors.get_mut(fd_num) {
                        f.flags |= 0x0080_0000;
                    }
                }
                return fd_num as i64;
            }
            Err(e) => return crate::subsys::linux::errno::vfs_err(e),
        }
    }

    // ── /dev/vport0p0 — QGA transport (virtio-serial port 0, Phase QGA-1) ─
    // Returns ENODEV when QGA was not compiled in or no virtio-serial-pci
    // device was discovered during PCI scan, so the userspace daemon
    // (Phase QGA-2) can probe-and-fall-back cleanly.
    if path == "/dev/vport0p0" {
        #[cfg(feature = "qga")]
        {
            if !crate::drivers::virtio_serial::is_available() {
                return -19; // ENODEV
            }
            match crate::vfs::open(pid, path, flags as u32) {
                Ok(fd_num) => {
                    let mut procs = crate::proc::PROCESS_TABLE.lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                        if let Some(Some(f)) = p.file_descriptors.get_mut(fd_num) {
                            f.flags |= 0x0040_0000;
                        }
                    }
                    return fd_num as i64;
                }
                Err(e) => return crate::subsys::linux::errno::vfs_err(e),
            }
        }
        #[cfg(not(feature = "qga"))]
        { return -19; } // ENODEV
    }

    // ── PTY: /dev/ptmx → allocate pair, return master fd ─────────────────
    if path == "/dev/ptmx" {
        return match crate::drivers::pty::alloc() {
            Some(pty_n) => {
                let fd = crate::vfs::FileDescriptor::pty_master(pty_n);
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    let slot = p.file_descriptors.iter().position(|s| s.is_none()).unwrap_or_else(|| {
                        p.file_descriptors.push(None);
                        p.file_descriptors.len() - 1
                    });
                    p.file_descriptors[slot] = Some(fd);
                    slot as i64
                } else {
                    -22
                }
            }
            None => -24, // EMFILE
        };
    }
    // ── PTY: /dev/pts/N → return slave fd ────────────────────────────────
    if path.starts_with("/dev/pts/") {
        if let Ok(n) = path["/dev/pts/".len()..].parse::<u8>() {
            let fd = crate::vfs::FileDescriptor::pty_slave(n);
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                let slot = p.file_descriptors.iter().position(|s| s.is_none()).unwrap_or_else(|| {
                    p.file_descriptors.push(None);
                    p.file_descriptors.len() - 1
                });
                p.file_descriptors[slot] = Some(fd);
                return slot as i64;
            }
        }
        return -2; // ENOENT
    }

    match crate::vfs::open(pid, path, flags as u32) {
        Ok(fd_num) => {
            // Special character devices: tag the fd with a device kind flag so
            // fd_read/fd_write can give them proper behaviour.
            //   bit 26 (0x0400_0000) = /dev/null
            //   bit 25 (0x0200_0000) = /dev/zero
            //   bit 24 (0x0100_0000) = /dev/urandom | /dev/random
            let dev_flag: u32 = match path {
                "/dev/null"                    => 0x0400_0000,
                "/dev/zero"                    => 0x0200_0000,
                "/dev/urandom" | "/dev/random" => 0x0100_0000,
                _ => 0,
            };
            if dev_flag != 0 {
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = p.file_descriptors.get_mut(fd_num) {
                        f.flags |= dev_flag;
                    }
                }
            }
            fd_num as i64
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// Linux stat(pathname, statbuf) — pathname is a C string, Linux stat layout.
fn sys_stat_linux(pathname: u64, stat_buf: u64) -> i64 {
    // Pointer validation is done at the user/kernel boundary
    // (dispatch_body arms 4/6) — see sys_open_linux for the rationale.
    let path_bytes = read_cstring_from_user(pathname);
    let path = match core::str::from_utf8(&path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    // Per stat(2): "If pathname is relative, then it is interpreted
    // relative to the current working directory of the calling process."
    // crate::vfs::stat is CWD-blind so we resolve here.
    let resolved: alloc::string::String = if path.starts_with('/') {
        alloc::string::String::from(path)
    } else {
        const AT_FDCWD: i64 = -100;
        match resolve_at_path(AT_FDCWD as u64, pathname) {
            Ok(p) => p,
            Err(e) => return e,
        }
    };
    match crate::vfs::stat(resolved.as_str()) {
        Ok(st) => {
            fill_linux_stat(stat_buf as *mut u8, &st);
            0
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// Linux fstat(fd, statbuf) — uses Linux stat layout.
fn sys_fstat_linux(fd_num: usize, stat_buf: *mut u8) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc_entry = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let fd = match proc_entry.file_descriptors.get(fd_num).and_then(|f| f.as_ref()) {
        Some(fd) => fd,
        None => return -9,
    };

    if fd.is_console {
        let st = crate::vfs::FileStat {
            inode: 0,
            file_type: crate::vfs::FileType::CharDevice,
            size: 0,
            permissions: 0o666,
            created: 0,
            modified: 0,
            accessed: 0,
        };
        fill_linux_stat(stat_buf, &st);
        return 0;
    }

    let mount_idx = fd.mount_idx;
    let inode = fd.inode;
    drop(procs);

    // Snapshot the Arc<FS> under the MOUNTS lock and drop the lock before
    // dispatching stat().  The ext2/fat32/ntfs stat paths reach virtio block
    // I/O which calls schedule(); holding the non-yielding MOUNTS spinlock
    // across that yields a cross-thread deadlock on SMP (confirmed GDB
    // autopsy: vfork parent spins on MOUNTS at resolve_path while the holder
    // is blocked in virtio wait_completion with MOUNTS still held).
    // Per POSIX fstat(2): the call must not hold any non-reentrant kernel
    // lock across a potential blocking I/O operation.
    match crate::vfs::fs_at(mount_idx) {
        Some((fs, _)) => match fs.stat(inode) {
            Ok(st) => {
                fill_linux_stat(stat_buf, &st);
                0
            }
            Err(e) => crate::subsys::linux::errno::vfs_err(e),
        },
        None => -9,
    }
}

/// Linux chdir(pathname) — pathname is a C string.
fn sys_chdir_linux(pathname: u64) -> i64 {
    let path_bytes = read_cstring_from_user(pathname);
    crate::syscall::sys_chdir(path_bytes.as_ptr(), path_bytes.len())
}

/// fchdir(fd) — change CWD to the directory referred to by `fd`.
fn sys_fchdir_linux(fd: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let open_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3, // ESRCH
        };
        let fd_idx = fd as usize;
        if fd_idx >= proc.file_descriptors.len() { return -9; } // EBADF
        match &proc.file_descriptors[fd_idx] {
            Some(f) => f.open_path.clone(),
            None => return -9,
        }
    };
    if open_path.is_empty() { return -9; } // EBADF — path unknown
    crate::syscall::sys_chdir(open_path.as_ptr(), open_path.len())
}

/// faccessat(dirfd, pathname, mode, flags) — access check relative to dirfd.
fn sys_faccessat_linux(dirfd: u64, pathname: u64, mode: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    // If AT_FDCWD or an absolute path, behave like access()
    if dirfd as i64 == AT_FDCWD {
        return sys_access(pathname, mode);
    }
    // Try to get the base directory from the fd and reconstruct full path
    let pid = crate::proc::current_pid_lockless();
    let base = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let idx = dirfd as usize;
        if idx >= proc.file_descriptors.len() { return -9; }
        match &proc.file_descriptors[idx] {
            Some(f) => f.open_path.clone(),
            None => return -9,
        }
    };
    let rel_bytes = read_cstring_from_user(pathname);
    let rel = match core::str::from_utf8(&rel_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };
    // Build full path: base + "/" + rel (if rel is absolute, use as-is)
    let full = if rel.starts_with('/') {
        alloc::string::String::from(rel)
    } else {
        let mut s = alloc::string::String::from(base.trim_end_matches('/'));
        s.push('/');
        s.push_str(rel);
        s
    };
    match crate::vfs::stat(&full) {
        Ok(_) => 0,
        Err(_) => -2, // ENOENT
    }
}

/// Resolve a user-supplied pathname against the process CWD if it is
/// relative.  Used by the bare-path Linux personality syscall wrappers
/// (mkdir/rmdir/unlink/chmod/chown/etc.) whose underlying
/// `crate::syscall::sys_*` helpers are CWD-blind by design.  Returns
/// the original byte buffer for absolute paths (avoids a clone) and a
/// freshly-allocated buffer for relative paths (cwd-prefixed +
/// NUL-terminated).
///
/// Per POSIX (IEEE Std 1003.1 §4.13 — Pathname resolution): "If a
/// pathname begins with the slash character ('/'), the predecessor of
/// the first filename in the pathname shall be taken to be the root
/// directory of the process [...]. If a pathname does not begin with a
/// slash, the predecessor of the first filename in the pathname shall
/// be taken to be the current working directory of the process."
fn resolve_user_path_to_owned(pathname: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    let raw = read_cstring_from_user(pathname);
    let s = match core::str::from_utf8(&raw) {
        Ok(s) => s,
        Err(_) => return Err(-22),
    };
    if s.starts_with('/') || s.is_empty() {
        // Absolute or empty — clone into an owned buffer so downstream
        // (which expects a contiguous ptr + len) can consume uniformly.
        let mut out = alloc::vec::Vec::with_capacity(raw.len());
        out.extend_from_slice(raw);
        return Ok(out);
    }
    // Relative — prefix CWD.
    const AT_FDCWD: i64 = -100;
    let full = resolve_at_path(AT_FDCWD as u64, pathname)?;
    let mut out = alloc::vec::Vec::with_capacity(full.len() + 1);
    out.extend_from_slice(full.as_bytes());
    out.push(0);
    Ok(out)
}

/// Linux mkdir(pathname, mode) — pathname is a C string.
fn sys_mkdir_linux(pathname: u64, _mode: u64) -> i64 {
    let path_bytes = match resolve_user_path_to_owned(pathname) {
        Ok(b) => b,
        Err(e) => return e,
    };
    // sys_mkdir reads path_len bytes (no NUL); we passed a NUL terminator
    // for absolute paths only in the relative branch — strip it.
    let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    crate::syscall::sys_mkdir(path_bytes.as_ptr(), len)
}

/// Linux rmdir(pathname) — pathname is a C string.
fn sys_rmdir_linux(pathname: u64) -> i64 {
    let path_bytes = match resolve_user_path_to_owned(pathname) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    crate::syscall::sys_rmdir(path_bytes.as_ptr(), len)
}

/// Linux unlink(pathname) — pathname is a C string.
fn sys_unlink_linux(pathname: u64) -> i64 {
    let path_bytes = match resolve_user_path_to_owned(pathname) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    crate::syscall::sys_unlink(path_bytes.as_ptr(), len)
}

/// Fill a Linux x86_64 `struct stat` buffer (144 bytes).
///
/// Layout:
///   dev:u64(0), ino:u64(8), nlink:u64(16), mode:u32(24), uid:u32(28),
///   gid:u32(32), pad:u32(36), rdev:u64(40), size:i64(48), blksize:i64(56),
///   blocks:i64(64), atime_sec:u64(72), atime_nsec:u64(80), mtime_sec:u64(88),
///   mtime_nsec:u64(96), ctime_sec:u64(104), ctime_nsec:u64(112), unused[3]:i64
const LINUX_STAT_SIZE: usize = 144;

fn fill_linux_stat(buf: *mut u8, st: &crate::vfs::FileStat) {
    // SMAP bracket — `buf` is a user pointer in the syscall path.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf, LINUX_STAT_SIZE) };
    for b in out.iter_mut() {
        *b = 0;
    }
    // dev (offset 0)
    out[0..8].copy_from_slice(&1u64.to_le_bytes());
    // ino (offset 8)
    out[8..16].copy_from_slice(&st.inode.to_le_bytes());
    // nlink (offset 16)
    out[16..24].copy_from_slice(&1u64.to_le_bytes());
    // mode (offset 24): Linux file type + permissions
    let mode: u32 = match st.file_type {
        crate::vfs::FileType::RegularFile => 0o100000 | st.permissions,
        crate::vfs::FileType::Directory   => 0o040000 | st.permissions,
        crate::vfs::FileType::SymLink     => 0o120000 | st.permissions,
        crate::vfs::FileType::CharDevice  => 0o020000 | st.permissions,
        crate::vfs::FileType::BlockDevice => 0o060000 | st.permissions,
        crate::vfs::FileType::Pipe        => 0o010000 | st.permissions,
        crate::vfs::FileType::EventFd     => 0o010000 | st.permissions, // FIFO
        crate::vfs::FileType::TimerFd | crate::vfs::FileType::SignalFd |
        crate::vfs::FileType::InotifyFd  => 0o010000 | st.permissions, // FIFO
        crate::vfs::FileType::PtyMaster | crate::vfs::FileType::PtySlave => 0o020000 | 0o666, // S_IFCHR
        crate::vfs::FileType::Socket      => 0o140000 | st.permissions, // S_IFSOCK
    };
    out[24..28].copy_from_slice(&mode.to_le_bytes());
    // uid (offset 28), gid (offset 32): 0
    // rdev (offset 40): 0
    // size (offset 48)
    out[48..56].copy_from_slice(&(st.size as i64).to_le_bytes());
    // blksize (offset 56)
    out[56..64].copy_from_slice(&4096i64.to_le_bytes());
    // blocks (offset 64): ceil(size / 512)
    let blocks = (st.size + 511) / 512;
    out[64..72].copy_from_slice(&(blocks as i64).to_le_bytes());
    // st_atim (offset 72): accessed time (seconds + nanoseconds)
    out[72..80].copy_from_slice(&(st.accessed as i64).to_le_bytes());
    // st_atim.tv_nsec (offset 80): 0
    // st_mtim (offset 88): modified time
    out[88..96].copy_from_slice(&(st.modified as i64).to_le_bytes());
    // st_mtim.tv_nsec (offset 96): 0
    // st_ctim (offset 104): created time (use as ctime)
    out[104..112].copy_from_slice(&(st.created as i64).to_le_bytes());
    // st_ctim.tv_nsec (offset 112): 0
}

// ── New Linux-specific syscalls ─────────────────────────────────────────────

/// arch_prctl(code, addr) — Set/get architecture-specific thread state.
///
/// Used by musl to set FS base for Thread-Local Storage (TLS).
pub fn sys_arch_prctl(code: u64, addr: u64) -> i64 {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    match code {
        ARCH_SET_FS => {
            // FS_BASE-trace probe — record the explicit user-mode WRMSR
            // path BEFORE the actual write.  This is the canonical TCB
            // setup path used by musl on x86_64 (per the musl libc
            // public docs: `arch_prctl(ARCH_SET_FS, tcb)`); without
            // this hook the very first FS.base write per thread would
            // be invisible to the diagnostic.  Diagnostic-only; gated
            // behind `fs-base-trace`.  Intel SDM Vol. 3A §3.4.4.1.
            #[cfg(feature = "fs-base-trace")]
            {
                let old_fs = unsafe { crate::hal::rdmsr(0xC000_0100) };
                crate::subsys::linux::fs_base_trace::record_event(
                    crate::subsys::linux::fs_base_trace::KIND_ARCH_PRCTL,
                    old_fs,
                    addr,
                    0,
                );
            }
            // Write to FS.base via MSR 0xC0000100 and persist in thread struct
            unsafe { crate::hal::wrmsr(0xC000_0100, addr); }
            // Update the thread's tls_base so scheduler restores it on re-schedule
            let tid = crate::proc::current_tid();
            {
                let mut threads = crate::proc::THREAD_TABLE.lock();
                if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
                    t.tls_base = addr;
                }
            }
            0
        }
        ARCH_GET_FS => {
            // Pointer validation is done at the user/kernel boundary
            // (dispatch_body arm 158).  Kernel-internal callers
            // (test_runner) pass kernel-resident u64 slots and bypass
            // — see sys_open_linux for the rationale.  Reject null
            // here regardless: a NULL out-ptr is meaningless for GET_FS
            // and the legacy "silently ignore" behaviour was a bug
            // (caller observes return=0 but never sees the FS base).
            if addr == 0 {
                return -14; // EFAULT
            }
            let fs = unsafe { crate::hal::rdmsr(0xC000_0100) };
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                *(addr as *mut u64) = fs;
            }
            0
        }
        ARCH_SET_GS => {
            unsafe { crate::hal::wrmsr(0xC000_0101, addr); }
            0
        }
        ARCH_GET_GS => {
            // Symmetric to ARCH_GET_FS above.
            if addr == 0 {
                return -14; // EFAULT
            }
            let gs = unsafe { crate::hal::rdmsr(0xC000_0101) };
            unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                *(addr as *mut u64) = gs;
            }
            0
        }
        _ => -22 // EINVAL
    }
}

/// set_tid_address(tidptr) — Store clear_child_tid pointer, return current TID.
/// glibc calls this during thread startup to register the address that should
/// be written to 0 and futex-woken when the thread exits (CLONE_CHILD_CLEARTID).
pub fn sys_set_tid_address(tidptr: u64) -> i64 {
    let tid = crate::proc::current_tid();
    if tidptr != 0 {
        // Pointer validation is done at the user/kernel boundary
        // (dispatch_body arm 218 — option (b) from the dispatch spec:
        // range-check at store time, decline the CLEAR_TID side effect
        // if the pointer is bad, still return TID per ABI).  Kernel-
        // internal callers (test_runner) pass kernel-resident slots and
        // bypass — see sys_open_linux for the rationale.
        let mut threads = crate::proc::THREAD_TABLE.lock();
        if let Some(t) = threads.iter_mut().find(|t| t.tid == tid) {
            t.clear_child_tid = tidptr;
        }
    }
    tid as i64
}

/// clock_gettime(clockid, tp) — Get time from a clock.
///
/// tp points to a struct timespec { u64 tv_sec, u64 tv_nsec }.
/// CLOCK_REALTIME (0): wall-clock time = boot_wall_secs + monotonic ticks.
/// CLOCK_MONOTONIC (1) and others: monotonic PIT ticks since boot.
///
/// Per `man 2 clock_gettime`, both clocks must advance smoothly at the
/// same rate (CLOCK_REALTIME differs from CLOCK_MONOTONIC only by an
/// epoch offset).  Re-reading the CMOS RTC on every call is incorrect:
/// the host RTC's second-tick edge does not align with our PIT-tick
/// edge, so two consecutive calls — or a vDSO read followed by a syscall
/// read — could observe the wall-clock seconds component running up to
/// 1 s ahead of the monotonic component.  glibc's `sem_timedwait` and
/// `pthread_cond_timedwait` then read CLOCK_REALTIME via vDSO, add a
/// short relative timeout, and pass the absolute deadline back to the
/// kernel; if the kernel's CLOCK_REALTIME has independently advanced
/// past the deadline, every wait returns ETIMEDOUT immediately.
///
/// The fix is to compute CLOCK_REALTIME from the boot-time wall-clock
/// seconds (`vdso::wall_secs_at_boot()`) plus the monotonic tick delta —
/// the same formula as `__vdso_clock_gettime` (see `kernel/vdso/vdso.S`).
pub fn sys_clock_gettime(clk_id: u64, tp: u64) -> i64 {
    // clk_id values per clock_gettime(2): 0=REALTIME, 1=MONOTONIC,
    // 4=MONOTONIC_RAW, 5=REALTIME_COARSE, 6=MONOTONIC_COARSE.
    const CLOCK_REALTIME:         u64 = 0;
    const CLOCK_MONOTONIC:        u64 = 1;
    const CLOCK_MONOTONIC_RAW:    u64 = 4;
    const CLOCK_REALTIME_COARSE:  u64 = 5;
    const CLOCK_MONOTONIC_COARSE: u64 = 6;
    if tp == 0 {
        return -22; // EINVAL
    }
    // Pointer validation is done at the user/kernel boundary
    // (dispatch_body arm 228).  Kernel-internal callers (test_runner,
    // futex absolute-deadline helpers) pass kernel-resident timespecs
    // and bypass — see sys_open_linux for the rationale.
    let _ = CLOCK_MONOTONIC; // suppress unused warning

    // HRES paths use TSC-derived ns — identical to the vDSO fast path so
    // futex absolute deadlines stay coherent.  COARSE paths use the 10 ms
    // tick counter per clock_gettime(2) "coarse resolution" semantics.
    //
    // Record/replay override: when `--features record-replay` is on, all
    // clocks (HRES and COARSE) are derived from the frozen virtual tick
    // counter `crate::record_replay::KERNEL_VIRTUAL_TICKS`.  This makes
    // `pthread_cond_timedwait` deadlines reproducible across runs at the
    // cost of breaking real wall-time accuracy; the trade is correct for
    // a diagnostic feature gated off by default.  Refs: POSIX
    // `clock_gettime(3)` and kernel.org
    // `Documentation/timers/timekeeping.rst`.
    let is_coarse = clk_id == CLOCK_REALTIME_COARSE || clk_id == CLOCK_MONOTONIC_COARSE;
    #[cfg(feature = "record-replay")]
    let (secs, nsecs) = { let _ = is_coarse; crate::record_replay::virtual_clock() };
    #[cfg(not(feature = "record-replay"))]
    let (secs, nsecs) = if is_coarse {
        let ticks = crate::arch::x86_64::irq::get_ticks();
        let mono_secs = ticks / 100;
        let sub_ns = (ticks % 100) * 10_000_000u64;
        (mono_secs, sub_ns)
    } else {
        let ns_total = crate::proc::vdso::monotonic_ns();
        if ns_total == 0 {
            // Calibration not yet published — fall back to tick granularity.
            let ticks = crate::arch::x86_64::irq::get_ticks();
            (ticks / 100, (ticks % 100) * 10_000_000u64)
        } else {
            (ns_total / 1_000_000_000, ns_total % 1_000_000_000)
        }
    };

    let is_realtime = clk_id == CLOCK_REALTIME || clk_id == CLOCK_REALTIME_COARSE;
    let _ = CLOCK_MONOTONIC_RAW;
    // Record/replay: pin the wall-clock epoch to a constant (the unix
    // timestamp 1_700_000_000 → 2023-11-14T22:13:20Z) instead of reading
    // the CMOS RTC, which is the only remaining non-deterministic input
    // into CLOCK_REALTIME.  Picked as a recognisable round number that
    // also sits inside the post-Y2038 safe window for future-dated
    // certificate validation paths.
    #[cfg(feature = "record-replay")]
    const RR_WALL_EPOCH: u64 = 1_700_000_000;
    let secs = if is_realtime {
        #[cfg(feature = "record-replay")]
        { RR_WALL_EPOCH.saturating_add(secs) }
        #[cfg(not(feature = "record-replay"))]
        { crate::proc::vdso::wall_secs_at_boot().saturating_add(secs) }
    } else {
        secs
    };

    // SMAP bracket — `tp` is a user-VA timespec pointer.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let buf = unsafe { core::slice::from_raw_parts_mut(tp as *mut u8, 16) };
    buf[0..8].copy_from_slice(&secs.to_le_bytes());
    buf[8..16].copy_from_slice(&nsecs.to_le_bytes());
    0
}

/// mprotect(addr, len, prot) — Change protection on memory region.
///
/// Walks the page table for every mapped page in [addr, addr+len) and updates
/// the PTE flags to match the requested protection.  Also updates the VMA prot
/// field so future page-fault allocations use the right flags.
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    use crate::mm::vma::{page_align_down, page_align_up, PROT_READ, PROT_WRITE, PROT_EXEC};
    use crate::mm::vmm::{read_pte, write_pte, PAGE_PRESENT, PAGE_WRITABLE,
                         PAGE_USER, PAGE_NO_EXECUTE};

    if len == 0 {
        return 0;
    }

    // Must be page-aligned.
    if addr & 0xFFF != 0 {
        return -22; // EINVAL
    }

    let base  = page_align_down(addr);
    let end   = page_align_up(addr.wrapping_add(len));
    let prot  = prot as u32;
    let pid   = crate::proc::current_pid_lockless();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let space = match proc.vm_space.as_mut() {
        Some(s) => s,
        None => return -22,
    };
    let cr3 = space.cr3;

    // W216 H_5j-B: mprotect rewrites VMA prot/areas in place; bump generation
    // to invalidate any in-flight PFH install loop that snapshotted the old
    // VMA before this call.
    space.generation.fetch_add(1, core::sync::atomic::Ordering::Release);

    // Update VMA prot fields that overlap this range, splitting VMAs as needed
    // so that only the exact [base, end) portion gets the new prot.
    let new_prot = prot;
    let mut i = 0;
    while i < space.areas.len() {
        let vma_base = space.areas[i].base;
        let vma_end  = space.areas[i].end();
        let old_prot = space.areas[i].prot;
        let flags    = space.areas[i].flags;
        let backing  = space.areas[i].backing.clone();
        let name     = space.areas[i].name;

        // No overlap — skip
        if vma_end <= base || vma_base >= end {
            i += 1;
            continue;
        }

        // Fully covered — just update in place, no split
        if vma_base >= base && vma_end <= end {
            space.areas[i].prot = new_prot;
            i += 1;
            continue;
        }

        // Partial overlap — remove and re-insert as up to 3 pieces.
        // CRITICAL: for file-backed VMAs, each split piece must have its
        // file offset adjusted by (piece.base - original_vma_base) so that
        // demand-paging reads from the correct file position.
        space.areas.remove(i);
        let overlap_start = vma_base.max(base);
        let overlap_end   = vma_end.min(end);

        // Helper: adjust file offset in backing for a split piece
        let adjust_backing = |b: &crate::mm::vma::VmBacking, piece_base: u64| -> crate::mm::vma::VmBacking {
            match b {
                crate::mm::vma::VmBacking::File { mount_idx, inode, offset, elf_load_delta } => {
                    crate::mm::vma::VmBacking::File {
                        mount_idx: *mount_idx,
                        inode: *inode,
                        offset: offset + (piece_base - vma_base),
                        // delta is segment-level constant; unchanged by mprotect split
                        elf_load_delta: *elf_load_delta,
                    }
                }
                other => other.clone(),
            }
        };

        let mut pieces: alloc::vec::Vec<crate::mm::vma::VmArea> = alloc::vec::Vec::new();
        if vma_base < base {
            pieces.push(crate::mm::vma::VmArea {
                base: vma_base, length: base - vma_base,
                prot: old_prot, flags, backing: adjust_backing(&backing, vma_base), name,
            });
        }
        pieces.push(crate::mm::vma::VmArea {
            base: overlap_start, length: overlap_end - overlap_start,
            prot: new_prot, flags, backing: adjust_backing(&backing, overlap_start), name,
        });
        if vma_end > end {
            pieces.push(crate::mm::vma::VmArea {
                base: end, length: vma_end - end,
                prot: old_prot, flags, backing: adjust_backing(&backing, end), name,
            });
        }
        let n = pieces.len();
        for piece in pieces.into_iter().rev() {
            space.areas.insert(i, piece);
        }
        i += n;
    }

    // Walk every page and retag PTEs.  TLB invalidation is coalesced
    // into a single shootdown over [base, end) after the loop so that
    // mprotect of a 1000-page range issues one IPI not 1000.
    let mut page = base;
    while page < end {
        let pte = read_pte(cr3, page);
        if pte & PAGE_PRESENT != 0 {
            let phys = pte & 0x000F_FFFF_FFFF_F000;
            // Start from PRESENT | USER; add WRITABLE or NO_EXECUTE as needed.
            let mut new_flags = PAGE_PRESENT | PAGE_USER;
            if prot & PROT_WRITE != 0 {
                new_flags |= PAGE_WRITABLE;
            }
            if prot & PROT_EXEC == 0 {
                new_flags |= PAGE_NO_EXECUTE;
            }
            write_pte(cr3, page, phys | new_flags);
        }
        page = page.wrapping_add(0x1000);
    }
    if end > base {
        crate::mm::tlb::shootdown_range(cr3, base, end);
    }

    0
}

/// writev(fd, iov, iovcnt) — Write from multiple buffers.
pub fn sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    // struct iovec { void *iov_base; size_t iov_len; } = [u64; 2]
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; } // EINVAL: IOV_MAX per POSIX writev(2)
    // Range-validate iov_ptr is in user space and the entire array fits.
    // CWE-823: Use of Out-of-range Pointer Offset. Without this a caller
    // can pass a kernel address as iov_ptr and direct the kernel to read
    // arbitrary kernel memory as the iov_base/iov_len descriptor.
    //
    // Bypassed when called from dispatch_linux_kernel (KernelDispatchGuard):
    // kernel-test callers legitimately pass kernel-resident iovec arrays.
    // Intel SDM Vol. 3A §4.6.1: STAC/CLAC guards cover user-mode pages only;
    // kernel-VA accesses are always permitted in ring-0.
    if !crate::syscall::user_ptr_check_bypassed()
        && !crate::syscall::validate_user_ptr(iov_ptr, (iovcnt as usize).saturating_mul(16))
    {
        return -14; // EFAULT
    }
    // SMAP-bracketed copy of the iovec array into kernel memory so the
    // loop body below never re-derefs user storage.
    let iovecs_owned: alloc::vec::Vec<[u64; 2]> = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iovcnt as usize).to_vec()
    };
    let mut total = 0i64;
    for iov in &iovecs_owned {
        let base = iov[0];
        let len = iov[1] as usize;
        if len == 0 { continue; }
        let result = sys_write_linux(fd, base, len as u64);
        if result < 0 { return result; }
        total += result;
    }
    total
}

/// readv(fd, iov, iovcnt) — Scatter-gather read.
///
/// Reads from `fd` into multiple buffers described by the iovec array.
/// struct iovec { void *iov_base; size_t iov_len; } = [u64; 2] on x86_64.
fn sys_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; } // EINVAL: IOV_MAX per POSIX readv(2)
    // CWE-823: range-validate iov_ptr (see sys_writev for full rationale).
    // Bypassed when called from dispatch_linux_kernel (KernelDispatchGuard):
    // kernel-test callers legitimately pass kernel-resident iovec arrays.
    if !crate::syscall::user_ptr_check_bypassed()
        && !crate::syscall::validate_user_ptr(iov_ptr, (iovcnt as usize).saturating_mul(16))
    {
        return -14; // EFAULT
    }
    let iovecs_owned: alloc::vec::Vec<[u64; 2]> = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iovcnt as usize).to_vec()
    };
    let mut total = 0i64;
    for iov in &iovecs_owned {
        let base = iov[0];
        let len = iov[1] as usize;
        if len == 0 { continue; }
        let result = sys_read_linux(fd, base, len as u64);
        if result < 0 { return if total > 0 { total } else { result }; }
        total += result;
        if (result as usize) < len { break; } // short read — stop
    }
    total
}

/// fcntl(fd, cmd, arg) — File descriptor control.
fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    const F_DUPFD:    u64 = 0;
    const F_GETFD:    u64 = 1;
    const F_SETFD:    u64 = 2;
    const F_GETFL:    u64 = 3;
    const F_SETFL:    u64 = 4;
    const F_GETLK:    u64 = 5;
    const F_SETLK:    u64 = 6;
    const F_SETLKW:   u64 = 7;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const FD_CLOEXEC: u64 = 1;
    // struct flock (x86_64): l_type(i16@0), l_whence(i16@2), l_start(i64@8), l_len(i64@16), l_pid(i32@24)
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    let pid = crate::proc::current_pid_lockless();
    match cmd {
        F_GETLK | F_SETLK | F_SETLKW => {
            if arg == 0 { return -22; } // EINVAL: null flock pointer
            // SMAP bracket the three user-pointer field reads.
            let (l_type, l_start, l_len) = unsafe {
                let _g = crate::arch::x86_64::smap::UserGuard::new();
                (*(arg as *const i16),
                 *((arg + 8)  as *const i64) as u64,
                 *((arg + 16) as *const i64) as u64)
            };

            // Get fd's backing (mount_idx, inode).
            let (mount_idx, inode) = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                match procs.iter().find(|p| p.pid == pid)
                    .and_then(|p| p.file_descriptors.get(fd as usize)?.as_ref())
                {
                    Some(f) if !f.is_console => (f.mount_idx, f.inode),
                    _ => return -9, // EBADF
                }
            };

            if cmd == F_GETLK {
                let locks = crate::vfs::FILE_LOCKS.lock();
                let conflict = locks.iter().find(|l| {
                    l.mount_idx == mount_idx && l.inode == inode && l.pid != pid
                        && (l_type == F_WRLCK || l.lock_type == F_WRLCK)
                });
                if let Some(lk) = conflict {
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        *(arg as *mut i16)        = lk.lock_type;
                        *((arg + 8)  as *mut i64) = lk.start as i64;
                        *((arg + 16) as *mut i64) = lk.end as i64;
                        *((arg + 24) as *mut i32) = lk.pid as i32;
                    }
                } else {
                    unsafe {
                        let _g = crate::arch::x86_64::smap::UserGuard::new();
                        *(arg as *mut i16) = F_UNLCK;
                    }
                }
                return 0;
            }

            // F_SETLK / F_SETLKW — acquire or release.
            if l_type == F_UNLCK {
                crate::vfs::FILE_LOCKS.lock().retain(|l| {
                    !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid)
                });
                return 0;
            }
            // Check for conflict (we don't block for F_SETLKW — return EAGAIN).
            {
                let locks = crate::vfs::FILE_LOCKS.lock();
                if locks.iter().any(|l| {
                    l.mount_idx == mount_idx && l.inode == inode && l.pid != pid
                        && (l_type == F_WRLCK || l.lock_type == F_WRLCK)
                }) {
                    return -11; // EAGAIN
                }
            }
            let mut locks = crate::vfs::FILE_LOCKS.lock();
            locks.retain(|l| !(l.mount_idx == mount_idx && l.inode == inode && l.pid == pid));
            locks.push(crate::vfs::FileLockEntry {
                mount_idx, inode, pid,
                start: l_start, end: l_len, lock_type: l_type,
            });
            0
        }
        F_DUPFD => crate::syscall::sys_dup(fd as usize),
        F_DUPFD_CLOEXEC => {
            let newfd = crate::syscall::sys_dup(fd as usize);
            if newfd >= 0 {
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(f)) = proc.file_descriptors.get_mut(newfd as usize) {
                        f.cloexec = true;
                    }
                }
            }
            newfd
        }
        F_GETFD => {
            let procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get(fd as usize) {
                    return if f.cloexec { FD_CLOEXEC as i64 } else { 0 };
                }
            }
            -9 // EBADF
        }
        F_SETFD => {
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get_mut(fd as usize) {
                    f.cloexec = (arg & FD_CLOEXEC) != 0;
                    return 0;
                }
            }
            -9 // EBADF
        }
        F_GETFL => {
            let procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get(fd as usize) {
                    return (f.flags & 0x0FFF) as i64; // return access mode + status flags
                }
            }
            -9 // EBADF
        }
        F_SETFL => {
            // Per `man 2 fcntl`: F_SETFL sets the file status flags portion
            // of `f.flags` (O_APPEND, O_NONBLOCK, O_ASYNC, O_DIRECT,
            // O_NOATIME).  The access mode (O_RDONLY/O_WRONLY/O_RDWR) and
            // file-creation flags (O_CREAT etc.) are not affected.
            //
            // We persist O_NONBLOCK (0x0800) and O_APPEND (0x0400) so that
            // subsequent read/write calls on eventfds, pipes, and sockets
            // can honour the documented blocking semantics.
            const SETTABLE: u64 = 0x0800 | 0x0400; // O_NONBLOCK | O_APPEND
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                if let Some(Some(f)) = proc.file_descriptors.get_mut(fd as usize) {
                    f.flags = (f.flags & !(SETTABLE as u32))
                        | ((arg as u32) & (SETTABLE as u32));
                    return 0;
                }
            }
            -9 // EBADF
        }
        // F_SETPIPE_SZ / F_GETPIPE_SZ — pipe capacity control (fcntl(2)).
        //
        // Per fcntl(2): F_SETPIPE_SZ changes the pipe's ring capacity; the
        // kernel rounds the request up (power of two, floor PIPE_BUF) and
        // returns the actual capacity.  EBUSY when the new capacity cannot
        // hold the currently buffered bytes; EPERM when the request exceeds
        // the pipe-max-size limit.  F_GETPIPE_SZ returns the capacity.
        // Both return EBADF when the descriptor does not refer to a pipe.
        1031 /* F_SETPIPE_SZ */ => {
            if !crate::syscall::is_pipe_fd(pid, fd as usize) { return -9; } // EBADF
            if arg == 0 { return -22; } // EINVAL
            let pipe_id = crate::syscall::get_pipe_id(pid, fd as usize);
            match crate::ipc::pipe::pipe_set_capacity(pipe_id, arg as usize) {
                Ok(cap) => cap as i64,
                Err(e) => e as i64,
            }
        }
        1032 /* F_GETPIPE_SZ */ => {
            if !crate::syscall::is_pipe_fd(pid, fd as usize) { return -9; } // EBADF
            let pipe_id = crate::syscall::get_pipe_id(pid, fd as usize);
            match crate::ipc::pipe::pipe_capacity(pipe_id) {
                Some(cap) => cap as i64,
                None => -9, // EBADF — pipe vanished
            }
        }
        // F_ADD_SEALS / F_GET_SEALS — memfd sealing API.
        //
        // Per fcntl(2): F_ADD_SEALS adds the seals in `arg` to the inode's
        // seal set.  The fd must be writable and the inode must have been
        // created with MFD_ALLOW_SEALING; otherwise -EPERM is returned.
        // Once F_SEAL_SEAL is set, no further seals may be added (-EPERM).
        // Unknown seal bits return -EINVAL.
        //
        // F_GET_SEALS returns the current seal mask, or 0 if the inode is
        // not sealing-capable (matches Linux behaviour — not an error).
        1033 /* F_ADD_SEALS */ => {
            // Resolve the inode for this fd.
            let inode_opt = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid).and_then(|p| {
                    p.file_descriptors.get(fd as usize)
                        .and_then(|f| f.as_ref())
                        .map(|f| f.inode)
                })
            };
            let inode = match inode_opt {
                Some(i) => i,
                None    => return -9, // EBADF
            };
            let rc = memfd_seals_add(inode, arg as u32);
            if rc == -22 {
                -22 // EINVAL — unknown seal bits
            } else if rc < 0 {
                -1  // EPERM — not sealing-capable or F_SEAL_SEAL already set
            } else {
                0
            }
        }
        1034 /* F_GET_SEALS */ => {
            // Resolve the inode for this fd.
            let inode_opt = {
                let procs = crate::proc::PROCESS_TABLE.lock();
                procs.iter().find(|p| p.pid == pid).and_then(|p| {
                    p.file_descriptors.get(fd as usize)
                        .and_then(|f| f.as_ref())
                        .map(|f| f.inode)
                })
            };
            match inode_opt {
                None        => -9, // EBADF
                Some(inode) => memfd_seals_get(inode).unwrap_or(0) as i64,
            }
        }
        _ => -22 // EINVAL
    }
}

/// sendfile(out_fd, in_fd, offset_ptr, count) — Copy data between file descriptors.
///
/// If offset_ptr is non-NULL, reads from *offset_ptr rather than in_fd's current
/// position, and updates *offset_ptr to reflect bytes read (in_fd's offset unchanged).
/// If offset_ptr is NULL, uses and advances in_fd's current file offset.
fn sys_sendfile(out_fd: usize, in_fd: usize, offset_ptr: u64, count: usize) -> i64 {
    if count == 0 { return 0; }
    let max_chunk: usize = 65536; // send at most 64 KiB at a time
    let len = count.min(max_chunk);
    let pid = crate::proc::current_pid_lockless();

    // Snapshot in_fd info and the read offset.
    let (in_mount, in_inode, in_offset_cur) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p, None => return -3,
        };
        match proc.file_descriptors.get(in_fd).and_then(|f| f.as_ref()) {
            Some(f) => (f.mount_idx, f.inode, f.offset),
            None => return -9,
        }
    };
    // Per sendfile(2): if `offset` is non-NULL, kernel reads the starting
    // offset from `*offset` and writes the post-read offset back on success.
    // Validate the 8-byte range and bracket the read with STAC/CLAC so the
    // supervisor access to a user page does not raise #PF when SMAP is
    // active (Intel SDM Vol. 3A §4.6).  An invalid pointer must surface as
    // EFAULT (errno 14), per the man page.
    let read_offset: u64 = if offset_ptr != 0 {
        if !crate::syscall::validate_user_ptr(offset_ptr, 8) {
            return -14; // EFAULT
        }
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::read_unaligned(offset_ptr as *const u64)
        }
    } else {
        in_offset_cur
    };

    // Read data from in_fd into a heap buffer.
    // Snapshot the Arc<FS> under MOUNTS and drop the lock before dispatching
    // read() — the block I/O path may call schedule() (virtio wait_completion),
    // and holding the non-yielding MOUNTS spinlock across that yields an SMP
    // deadlock.  Per sendfile(2) / POSIX read(2): no kernel-internal lock may
    // be held across blocking I/O.
    let mut buf: alloc::vec::Vec<u8> = alloc::vec![0u8; len];
    let n = match crate::vfs::fs_at(in_mount) {
        Some((fs, _)) => match fs.read(in_inode, read_offset, &mut buf) {
            Ok(n) => n,
            Err(_) => return -5,
        },
        None => return -9,
    };
    if n == 0 { return 0; }
    buf.truncate(n);

    // Snapshot out_fd info.
    let out_info = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p, None => return -3,
        };
        proc.file_descriptors.get(out_fd).and_then(|f| f.as_ref()).map(|f| {
            (f.is_console, f.file_type, f.mount_idx, f.inode, f.offset,
             f.flags & 0x8000_0001)
        })
    };
    let (is_console, file_type, out_mount, out_inode, out_offset, pipe_flags) = match out_info {
        Some(x) => x, None => return -9,
    };
    if is_console {
        crate::serial_print!("{}", core::str::from_utf8(&buf).unwrap_or("?"));
    } else if file_type == crate::vfs::FileType::Pipe {
        if pipe_flags & 1 != 0 {
            crate::ipc::pipe::pipe_write(out_inode, &buf);
        } else {
            return -9;
        }
    } else {
        // Same snapshot-Arc-then-drop convention as the read path above:
        // drop MOUNTS before dispatching write() which may block on I/O.
        match crate::vfs::fs_at(out_mount) {
            Some((fs, _)) => {
                let n_w = fs.write(out_inode, out_offset, &buf).unwrap_or(0);
                // Page-cache coherency: same contract as `vfs::fd_write`
                // (POSIX mmap(2) MAP_SHARED + write(2) visibility).
                if n_w > 0 {
                    crate::mm::cache::update_range(
                        out_mount, out_inode, out_offset, &buf[..n_w],
                    );
                }
                let mut procs = crate::proc::PROCESS_TABLE.lock();
                if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                    if let Some(Some(fd)) = proc.file_descriptors.get_mut(out_fd) {
                        fd.offset += n as u64;
                    }
                }
            }
            None => return -9,
        }
    }

    // Update the read offset.  Per sendfile(2): on a non-NULL offset
    // pointer the kernel writes back the post-read offset.  validate_user_ptr
    // already passed at the top of the function (we never NULL it between
    // there and here), but we re-bracket with STAC/CLAC because the write
    // touches a user page (Intel SDM Vol. 3A §4.6).
    if offset_ptr != 0 {
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::write_unaligned(offset_ptr as *mut u64, read_offset + n as u64);
        }
    } else {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(fd)) = proc.file_descriptors.get_mut(in_fd) {
                fd.offset += n as u64;
            }
        }
    }

    n as i64
}

/// access(pathname, mode) — Check user's permissions for a file.
///
/// Per access(2):
///   - F_OK (0): existence only — return 0 if the path resolves, -ENOENT otherwise.
///   - R_OK (4): readable — granted unconditionally (no per-user perms yet).
///   - W_OK (2): writable — denied with -EACCES on a read-only mount or when
///     the inode mode lacks any of the write bits (mode & 0o222 == 0).
///   - X_OK (1): executable — granted for directories (modulo the readability
///     check above) or when the inode mode has any execute bit set.  On a
///     `noexec` mount, X_OK is denied with -EACCES per mount(2).
///
/// The mount-flag set (ro / noexec) is derived from procfs::mount_opts_for
/// which currently keys on (mountpoint, fstype).  Replacing that helper with
/// per-mount flag plumbing later changes nothing here.
fn sys_access(pathname: u64, mode: u64) -> i64 {
    const F_OK: u64 = 0;
    const X_OK: u64 = 1;
    const W_OK: u64 = 2;
    const R_OK: u64 = 4;

    // Pointer validation is done at the user/kernel boundary
    // (dispatch_body arm 21) — see sys_open_linux for the rationale.

    let path_bytes = read_cstring_from_user(pathname);
    let path_raw = match core::str::from_utf8(&path_bytes) {
        Ok(s) => s,
        Err(_) => return -22, // EINVAL
    };
    // Per access(2): "If pathname is relative, then it is interpreted
    // relative to the current working directory of the calling process."
    let resolved_owned: alloc::string::String = if path_raw.starts_with('/') {
        alloc::string::String::from(path_raw)
    } else {
        const AT_FDCWD: i64 = -100;
        match resolve_at_path(AT_FDCWD as u64, pathname) {
            Ok(p) => p,
            Err(e) => return e,
        }
    };
    let path: &str = resolved_owned.as_str();

    // Resolve to (mount_idx, inode).  Existence failure → -ENOENT.
    let (mount_idx, inode) = match crate::vfs::resolve_path(path) {
        Ok(t) => t,
        Err(_) => return -2, // ENOENT
    };

    // F_OK alone: existence check passed already.
    if mode == F_OK {
        return 0;
    }

    // Snapshot the Arc<FS>, mount path, and fstype under the MOUNTS lock,
    // then drop the lock before dispatching stat() which may block on I/O.
    // Holding the non-yielding MOUNTS spinlock across a schedule() point
    // (reached via virtio block I/O) causes an SMP deadlock — same class as
    // the fstat/sendfile fix.  Per POSIX access(2): no reentrant lock may
    // be held across a blocking file-system call.
    let (mount_path, fstype, fs) = {
        let mounts = crate::vfs::MOUNTS.lock();
        match mounts.get(mount_idx) {
            Some(m) => (m.path.clone(), alloc::string::String::from(m.fs.name()), m.fs.clone()),
            None => return -2,
        }
    };
    let st = match fs.stat(inode) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let opts = crate::vfs::procfs::mount_opts_for(mount_path.as_str(), fstype.as_str());
    let mount_ro     = opts.split(',').any(|t| t == "ro");
    let mount_noexec = opts.split(',').any(|t| t == "noexec");
    let perm = st.permissions;

    // R_OK: we have no per-user / per-process credentials yet.  Treat every
    // resolvable inode as readable.

    // W_OK: deny on read-only mount, or if the mode bits lack any write bit.
    if mode & W_OK != 0 {
        if mount_ro || (perm & 0o222) == 0 {
            return -13; // EACCES
        }
    }

    // X_OK: directories are "executable" when readable (path-traversal bit).
    // Regular files need at least one mode_t exec bit AND the mount must not
    // be `noexec`.  Per access(2), X_OK on a noexec mount returns -EACCES.
    if mode & X_OK != 0 {
        let is_dir = st.file_type == crate::vfs::FileType::Directory;
        if is_dir {
            // No additional mode-bit gating for directory traversal.
            // The noexec mount flag does not block directory traversal —
            // it blocks only PROT_EXEC mappings of files on the mount.
        } else if mount_noexec || (perm & 0o111) == 0 {
            return -13; // EACCES
        }
    }

    // Sanity for unknown bits: per access(2), passing bits other than R_OK |
    // W_OK | X_OK | F_OK yields -EINVAL.  We accept any subset of those four
    // and reject anything else.
    if mode & !(R_OK | W_OK | X_OK | F_OK) != 0 {
        return -22; // EINVAL
    }

    0
}

/// gettimeofday(tv, tz) — Get the time of day.
///
/// tv points to struct timeval { u64 tv_sec, u64 tv_usec }.
///
/// Per `man 2 gettimeofday`, this returns wall-clock time (seconds since
/// the UNIX epoch).  It must match `__vdso_gettimeofday` byte-for-byte:
///   tv_sec  = boot_wall_secs + ticks / TICK_HZ
///   tv_usec = (ticks % TICK_HZ) * US_PER_TICK
fn sys_gettimeofday(tv: u64, _tz: u64) -> i64 {
    if tv == 0 {
        return 0;
    }
    // Pointer validation is done at the user/kernel boundary
    // (dispatch_body arm 96).  Kernel-internal callers (none today, but
    // possible) bypass — see sys_open_linux for the rationale.
    // TSC-derived ns for vDSO/syscall parity; falls back to tick
    // granularity before TSC calibration is published (pre-apic::init).
    //
    // Record/replay: derive from the frozen virtual tick counter and a
    // pinned wall-clock epoch (1_700_000_000) so the (sec, usec) pair is
    // identical across runs of the same workload.  See
    // `clock_gettime(2)` (POSIX) and `crate::record_replay`.
    #[cfg(feature = "record-replay")]
    let (secs, sub_usecs) = {
        let (vsecs, vns) = crate::record_replay::virtual_clock();
        (1_700_000_000u64.saturating_add(vsecs), vns / 1000)
    };
    #[cfg(not(feature = "record-replay"))]
    let (secs, sub_usecs) = {
        let mono_ns = crate::proc::vdso::monotonic_ns();
        let (mono_secs, sub_usecs) = if mono_ns != 0 {
            (mono_ns / 1_000_000_000, (mono_ns % 1_000_000_000) / 1000)
        } else {
            let ticks = crate::arch::x86_64::irq::get_ticks();
            (ticks / 100, (ticks % 100) * 10_000)
        };
        let secs = crate::proc::vdso::wall_secs_at_boot().saturating_add(mono_secs);
        (secs, sub_usecs)
    };
    // SMAP bracket — `tv` is a user-VA timeval pointer.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let buf = unsafe { core::slice::from_raw_parts_mut(tv as *mut u8, 16) };
    buf[0..8].copy_from_slice(&secs.to_le_bytes());
    buf[8..16].copy_from_slice(&sub_usecs.to_le_bytes());
    0
}

/// getdents64(fd, dirp, count) — Read directory entries.
///
/// Each entry: { d_ino: u64, d_off: u64, d_reclen: u16, d_type: u8, d_name: [u8] }
fn sys_getdents64(fd: u64, buf: u64, count: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let (mount_idx, inode, offset, open_path) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd_entry = match proc_entry.file_descriptors.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return -9,
        };
        (fd_entry.mount_idx, fd_entry.inode, fd_entry.offset, fd_entry.open_path.clone())
    };

    // ── Special case: /proc/self/fd — synthesise entries from the fd table ──
    if open_path == "/proc/self/fd" || open_path == "/proc/self/fd/" {
        return getdents64_proc_fd(pid, fd as usize, buf, count, offset);
    }

    // Snapshot Arc<FS> under MOUNTS, drop the lock, then dispatch readdir().
    // ext2::readdir issues block I/O (read_block → virtio wait_completion →
    // schedule()); holding the non-yielding MOUNTS spinlock across that point
    // causes the same SMP deadlock as fstat/sendfile.  Per POSIX getdents(3):
    // no non-reentrant lock may span a blocking directory-read operation.
    let entries = match crate::vfs::fs_at(mount_idx) {
        Some((fs, _)) => match fs.readdir(inode) {
            Ok(e) => e,
            Err(e) => return crate::subsys::linux::errno::vfs_err(e),
        },
        None => return -9,
    };

    // SMAP bracket — `buf` is a user-VA pointer the dirent records are
    // marshalled into.
    let _smap_g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
    let mut pos = 0usize;
    let mut entry_idx = offset as usize;

    while entry_idx < entries.len() {
        let (ref name, ino, ft) = entries[entry_idx];
        let name_bytes = name.as_bytes();
        // d_reclen: 8(ino) + 8(off) + 2(reclen) + 1(type) + name_len + 1(null) + padding
        let fixed_len = 19 + name_bytes.len() + 1;
        let reclen = (fixed_len + 7) & !7; // align to 8

        if pos + reclen > count as usize {
            break;
        }

        // d_ino (offset 0)
        out[pos..pos+8].copy_from_slice(&ino.to_le_bytes());
        // d_off (offset 8)
        out[pos+8..pos+16].copy_from_slice(&((entry_idx + 1) as u64).to_le_bytes());
        // d_reclen (offset 16)
        out[pos+16..pos+18].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_type (offset 18)
        out[pos+18] = match ft {
            crate::vfs::FileType::RegularFile => 8,  // DT_REG
            crate::vfs::FileType::Directory   => 4,  // DT_DIR
            crate::vfs::FileType::SymLink     => 10, // DT_LNK
            crate::vfs::FileType::CharDevice  => 2,  // DT_CHR
            crate::vfs::FileType::BlockDevice => 6,  // DT_BLK
            crate::vfs::FileType::Pipe        => 1,  // DT_FIFO
            crate::vfs::FileType::EventFd     => 1,  // DT_FIFO
            crate::vfs::FileType::TimerFd | crate::vfs::FileType::SignalFd |
            crate::vfs::FileType::InotifyFd  => 1,  // DT_FIFO
            crate::vfs::FileType::PtyMaster | crate::vfs::FileType::PtySlave => 2, // DT_CHR
            crate::vfs::FileType::Socket      => 12, // DT_SOCK
        };
        // d_name (offset 19)
        let nlen = name_bytes.len().min(reclen - 20);
        out[pos+19..pos+19+nlen].copy_from_slice(&name_bytes[..nlen]);
        out[pos+19+nlen] = 0; // null terminator
        // Zero padding
        for i in (pos+20+nlen)..pos+reclen {
            out[i] = 0;
        }

        pos += reclen;
        entry_idx += 1;
    }

    // Update the fd offset to track entries returned
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc_entry) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(fd_entry)) = proc_entry.file_descriptors.get_mut(fd as usize) {
                fd_entry.offset = entry_idx as u64;
            }
        }
    }

    pos as i64
}

/// Synthesise getdents64 output for the virtual /proc/self/fd directory.
///
/// Entries: "." and ".." (DT_DIR), then one DT_LNK entry per open fd.
/// `dir_fd` is the fd that was opened on "/proc/self/fd" — its offset is
/// updated so repeated calls advance through the listing correctly.
fn getdents64_proc_fd(pid: u64, dir_fd: usize, buf: u64, count: u64, start_idx: u64) -> i64 {
    // Snapshot the list of open (fd_number, open_path) pairs.
    let fds_snap: alloc::vec::Vec<(usize, alloc::string::String)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            p.file_descriptors.iter().enumerate()
                .filter_map(|(i, slot)| slot.as_ref().map(|f| (i, f.open_path.clone())))
                .collect()
        } else {
            return -3; // ESRCH
        }
    };

    // Virtual entries: [".", ".."] + one per open fd
    // We represent each as (name, inode, d_type).
    // d_type: DT_DIR=4, DT_LNK=10
    let mut virtual_entries: alloc::vec::Vec<(alloc::string::String, u64, u8)> = alloc::vec::Vec::new();
    virtual_entries.push((alloc::string::String::from("."),  100, 4));
    virtual_entries.push((alloc::string::String::from(".."), 99,  4));
    for (fd_num, _) in &fds_snap {
        let name = alloc::format!("{}", fd_num);
        let ino = 200 + *fd_num as u64;
        virtual_entries.push((name, ino, 10)); // DT_LNK
    }

    // SMAP bracket — `buf` is a user-VA pointer the dirent records are
    // marshalled into.
    let _smap_g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
    let mut pos = 0usize;
    let mut entry_idx = start_idx as usize;

    while entry_idx < virtual_entries.len() {
        let (ref name, ino, d_type) = virtual_entries[entry_idx];
        let name_bytes = name.as_bytes();
        let fixed_len = 19 + name_bytes.len() + 1; // all fixed fields + name + NUL
        let reclen = (fixed_len + 7) & !7;          // align to 8

        if pos + reclen > count as usize {
            break;
        }

        // d_ino [0..8]
        out[pos..pos+8].copy_from_slice(&ino.to_le_bytes());
        // d_off [8..16]
        out[pos+8..pos+16].copy_from_slice(&((entry_idx + 1) as u64).to_le_bytes());
        // d_reclen [16..18]
        out[pos+16..pos+18].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_type [18]
        out[pos+18] = d_type;
        // d_name [19..19+n+1]
        let nlen = name_bytes.len().min(reclen - 20);
        out[pos+19..pos+19+nlen].copy_from_slice(&name_bytes[..nlen]);
        out[pos+19+nlen] = 0;
        // zero padding
        for b in out[pos+20+nlen..pos+reclen].iter_mut() { *b = 0; }

        pos += reclen;
        entry_idx += 1;
    }

    // Persist updated offset so the next call resumes where we left off.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(f)) = p.file_descriptors.get_mut(dir_fd) {
                f.offset = entry_idx as u64;
            }
        }
    }

    pos as i64
}

/// openat(dirfd, pathname, flags, mode) — Open file relative to directory fd.
fn sys_openat(dirfd: u64, pathname: u64, flags: u64, mode: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    // Pointer validation is done at the user/kernel boundary (dispatch_body
    // arm 257) — see sys_open_linux for the rationale.
    if dirfd as i64 == AT_FDCWD {
        // Per openat(2) §AT_FDCWD: "If pathname is relative and dirfd is
        // the special value AT_FDCWD, pathname is interpreted relative to
        // the current working directory of the calling process."  The
        // downstream sys_open_linux → crate::vfs::open chain calls
        // resolve_path which is CWD-blind, so we need to resolve relative
        // paths HERE against the process CWD before handing off.
        let raw = read_cstring_from_user(pathname);
        let rel_str = match core::str::from_utf8(&raw) {
            Ok(s) => s,
            Err(_) => return -22, // EINVAL
        };
        if rel_str.starts_with('/') || rel_str.is_empty() {
            // Absolute path or empty (later rejected) — sys_open_linux is
            // the right entry; it handles SMAP, ring tracking, /proc/self
            // refresh, /dev/dsp routing, etc.
            return sys_open_linux(pathname, flags, mode);
        }
        // Relative path with AT_FDCWD — resolve against cwd, then call
        // straight into vfs::open with the absolute path.  We bypass
        // sys_open_linux's mainline because it re-reads pathname from
        // user memory and we have only a kernel-side string now.  The
        // /proc/self/* refresh and ring tracking are not needed for
        // CWD-relative cases (they fire only on absolute paths like
        // "/proc/self/maps").
        let full_path = match resolve_at_path(AT_FDCWD as u64, pathname) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let pid = crate::proc::current_pid_lockless();
        return match crate::vfs::open(pid, full_path.as_str(), flags as u32) {
            Ok(fd_num) => fd_num as i64,
            Err(e) => crate::subsys::linux::errno::vfs_err(e),
        };
    }

    // Real directory fd — resolve pathname relative to it.
    let path_bytes = read_cstring_from_user(pathname);
    let rel_path = match core::str::from_utf8(&path_bytes) {
        Ok(s) => s,
        Err(_) => return -22, // EINVAL
    };

    // If pathname is absolute, ignore dirfd.
    if rel_path.starts_with('/') {
        return sys_open_linux(pathname, flags, mode);
    }

    // Empty path with AT_EMPTY_PATH — not supported yet.
    if rel_path.is_empty() {
        return -22; // EINVAL
    }

    // Get the directory path from the dirfd.
    let pid = crate::proc::current_pid_lockless();
    // Resolve dirfd → directory path under PROCESS_TABLE, then drop the lock
    // explicitly before any ring::* call. Keeping ring access strictly
    // disjoint from PROCESS_TABLE prevents an ABBA against any other path
    // that takes the ring lock first and then a process-table lock.
    let dir_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3, // ESRCH
        };
        let fd_idx = dirfd as usize;
        let path = match proc_entry.file_descriptors.get(fd_idx).and_then(|f| f.as_ref()) {
            Some(fd) => fd.open_path.clone(),
            None => return -9, // EBADF
        };
        drop(procs);
        path
    };

    // Build full path: dir_path + "/" + rel_path
    let full_path = if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, rel_path)
    } else {
        alloc::format!("{}/{}", dir_path, rel_path)
    };

    // Attach the resolved path to the pending ring entry.
    #[cfg(feature = "firefox-test-core")]
    {
        let idx = crate::subsys::linux::syscall_ring::current_entry();
        crate::syscall::ring::set_path(pid, idx, &full_path);
    }

    // Open via the normal VFS path.
    match crate::vfs::open(pid, &full_path, flags as u32) {
        Ok(fd_num) => fd_num as i64,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// newfstatat(dirfd, pathname, statbuf, flags) — stat relative to directory fd.
fn sys_newfstatat(dirfd: u64, pathname: u64, statbuf: u64, flags: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    const AT_EMPTY_PATH: u64 = 0x1000;

    // AT_EMPTY_PATH with empty pathname → fstat the dirfd itself.
    if flags & AT_EMPTY_PATH != 0 {
        let path_bytes = read_cstring_from_user(pathname);
        if path_bytes.is_empty() {
            return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
        }
    }

    if pathname == 0 {
        return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
    }

    let path_bytes = read_cstring_from_user(pathname);
    if path_bytes.is_empty() {
        return sys_fstat_linux(dirfd as usize, statbuf as *mut u8);
    }
    let path_str = match core::str::from_utf8(&path_bytes) {
        Ok(s) => s,
        Err(_) => return -22,
    };

    // Absolute path or AT_FDCWD — resolve directly.
    if dirfd as i64 == AT_FDCWD || path_str.starts_with('/') {
        return sys_stat_linux(pathname, statbuf);
    }

    // Relative path with real dirfd — resolve relative to dirfd's path.
    let pid = crate::proc::current_pid_lockless();
    let dir_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd_idx = dirfd as usize;
        match proc_entry.file_descriptors.get(fd_idx).and_then(|f| f.as_ref()) {
            Some(fd) => fd.open_path.clone(),
            None => return -9, // EBADF
        }
    };

    let full_path = if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, path_str)
    } else {
        alloc::format!("{}/{}", dir_path, path_str)
    };

    match crate::vfs::stat(&full_path) {
        Ok(st) => {
            fill_linux_stat(statbuf as *mut u8, &st);
            0
        }
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// rt_sigaction for Linux ABI.
///
/// Linux struct kernel_sigaction:
///   sa_handler: u64, sa_flags: u64, sa_restorer: u64, sa_mask: [u64; 1]
///
/// Lock-ordering note: same recursive-spinlock hazard as `rt_sigprocmask` —
/// reading `act` or writing `oldact` may demand-page a user page whose fault
/// handler needs `PROCESS_TABLE`.  We perform the user reads first, then take
/// the lock to mutate signal state, then write the prior action back AFTER
/// releasing the lock.
fn sys_rt_sigaction_linux(sig: u64, act: u64, oldact: u64, _sigsetsize: u64) -> i64 {
    use crate::signal::{SigAction, SIGKILL, SIGSTOP, MAX_SIGNAL};

    const SA_RESTORER: u64 = 0x04000000;
    /// Minimum valid user-space pointer: reject anything below one page.
    const USER_PTR_MIN: u64 = 0x1000;
    /// Maximum valid user-space pointer (below the kernel half).
    const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;

    let sig = sig as u8;
    if sig == 0 || sig >= MAX_SIGNAL || sig == SIGKILL || sig == SIGSTOP {
        return -22;
    }

    if oldact != 0 && (oldact < USER_PTR_MIN || oldact >= USER_PTR_MAX) {
        return -14; // EFAULT
    }
    if act != 0 && (act < USER_PTR_MIN || act >= USER_PTR_MAX) {
        return -14; // EFAULT
    }

    // Step 1: read the requested new action from user memory FIRST, before any
    // kernel lock is held.  Demand-paging that user page may take
    // `PROCESS_TABLE`; doing it under our own held lock would deadlock.
    //
    // The Linux `struct kernel_sigaction` on x86_64 (per
    // `arch/x86/include/uapi/asm/signal.h`) is laid out as:
    //   u64 sa_handler;       // [0..8)
    //   u64 sa_flags;         // [8..16)
    //   u64 sa_restorer;      // [16..24)
    //   u64 sa_mask[1];       // [24..32) — sigset_t is a single u64 on x86_64
    let new_handler_addr: Option<u64>;
    let new_sa_flags: u64;
    let new_sa_mask: u64;
    let new_action: Option<SigAction>;
    if act != 0 {
        // SMAP-bracketed copy of the 32-byte sigaction into kernel mem.
        let mut inp = [0u8; 32];
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::copy_nonoverlapping(act as *const u8, inp.as_mut_ptr(), 32);
        }
        let handler_addr = u64::from_le_bytes(inp[0..8].try_into().unwrap());
        let sa_flags    = u64::from_le_bytes(inp[8..16].try_into().unwrap());
        let sa_restorer = u64::from_le_bytes(inp[16..24].try_into().unwrap());
        let sa_mask     = u64::from_le_bytes(inp[24..32].try_into().unwrap());
        let restorer = if sa_flags & SA_RESTORER != 0 && sa_restorer != 0 {
            sa_restorer
        } else {
            0 // use kernel trampoline
        };
        new_handler_addr = Some(handler_addr);
        new_sa_flags = sa_flags;
        new_sa_mask = sa_mask;
        new_action = Some(match handler_addr {
            0 => SigAction::Default,
            1 => SigAction::Ignore,
            addr => SigAction::Handler { addr, restorer },
        });
    } else {
        new_handler_addr = None;
        new_sa_flags = 0;
        new_sa_mask = 0;
        new_action = None;
    }
    let _ = new_handler_addr; // currently unused outside the SigAction variant

    // Step 2: take the lock, swap in the new action, and capture the prior
    // one for later write-back.  No user-pointer dereferences inside.
    let pid = crate::proc::current_pid_lockless();
    let prior_handler_addr: u64;
    let prior_restorer_addr: u64;
    let prior_sa_flags: u64;
    let prior_sa_mask: u64;
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let sig_state = match proc_entry.signal_state.as_mut() {
            Some(s) => s,
            None => return -1,
        };
        let (h, r) = match sig_state.actions[sig as usize] {
            SigAction::Default => (0u64, 0u64),
            SigAction::Ignore => (1u64, 0u64),
            SigAction::Handler { addr, restorer } => (addr, restorer),
        };
        prior_handler_addr  = h;
        prior_restorer_addr = r;
        prior_sa_flags = sig_state.action_flags[sig as usize];
        prior_sa_mask  = sig_state.action_mask[sig as usize];
        if let Some(new) = new_action {
            sig_state.actions[sig as usize] = new;
            sig_state.action_flags[sig as usize] = new_sa_flags;
            sig_state.action_mask[sig as usize]  = new_sa_mask;
        }
    }

    // Step 3: write the prior action back to user memory AFTER releasing the
    // lock so that a demand-page fault on `oldact` can resolve.  Per
    // `man 2 rt_sigaction`, all four words of the previous sigaction must
    // round-trip — Mozilla's IPC layer compares the value it set against
    // the value it gets back to detect ABI mismatches.
    if oldact != 0 {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&prior_handler_addr.to_le_bytes());
        out[8..16].copy_from_slice(&prior_sa_flags.to_le_bytes());
        out[16..24].copy_from_slice(&prior_restorer_addr.to_le_bytes());
        out[24..32].copy_from_slice(&prior_sa_mask.to_le_bytes());
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::copy_nonoverlapping(out.as_ptr(), oldact as *mut u8, 32);
        }
    }

    0
}

/// rt_sigprocmask for Linux ABI.
///
/// Per `sigprocmask(2)`: if `set` is non-NULL the kernel reads a `sigset_t`
/// from it; if `oldset` is non-NULL the kernel writes the prior mask there.
///
/// Lock-ordering note: a kernel-mode `#PF` triggered by demand-paging the
/// user `set` / `oldset` pages must be able to acquire `PROCESS_TABLE` to
/// resolve the fault.  Therefore we MUST NOT hold `PROCESS_TABLE` while
/// dereferencing user pointers — otherwise the recursive non-reentrant
/// spinlock attempt deadlocks the CPU.  The fix below splits the work into
/// (1) a user-memory read into a local buffer, (2) lock + mutate signal
/// state, (3) a user-memory write of the saved mask.  The race window is
/// invisible to userspace because `rt_sigprocmask` is documented as
/// per-thread serialized.
fn sys_rt_sigprocmask_linux(how: u64, set: u64, oldset: u64, _sigsetsize: u64) -> i64 {
    const USER_PTR_MIN: u64 = 0x1000;
    const USER_PTR_MAX: u64 = 0x0000_8000_0000_0000;
    if oldset != 0 && (oldset < USER_PTR_MIN || oldset >= USER_PTR_MAX) {
        return -14; // EFAULT
    }
    if set != 0 && (set < USER_PTR_MIN || set >= USER_PTR_MAX) {
        return -14; // EFAULT
    }

    const SIG_BLOCK: u64 = 0;
    const SIG_UNBLOCK: u64 = 1;
    const SIG_SETMASK: u64 = 2;
    if set != 0 && !matches!(how, SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK) {
        return -22; // EINVAL
    }

    // Step 1: read the requested new mask from user memory FIRST, before any
    // kernel lock is held.  Demand-paging that user page may take
    // `PROCESS_TABLE`; doing it under our own held lock would deadlock.
    let new_mask: Option<u64> = if set != 0 {
        let mut bytes = [0u8; 8];
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::copy_nonoverlapping(set as *const u8, bytes.as_mut_ptr(), 8);
        }
        Some(u64::from_le_bytes(bytes))
    } else {
        None
    };

    // Step 2: take the lock, fold in the new mask, capture the prior mask
    // for write-back.  No user-pointer dereferences inside this block.
    let pid = crate::proc::current_pid_lockless();
    let prior_mask: u64 = {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let sig_state = match proc_entry.signal_state.as_mut() {
            Some(s) => s,
            None => return -1,
        };
        let prior = sig_state.blocked;
        if let Some(nm) = new_mask {
            match how {
                SIG_BLOCK => sig_state.blocked |= nm,
                SIG_UNBLOCK => sig_state.blocked &= !nm,
                SIG_SETMASK => sig_state.blocked = nm,
                _ => unreachable!(), // already validated above
            }
            sig_state.blocked &= !((1u64 << crate::signal::SIGKILL)
                                  | (1u64 << crate::signal::SIGSTOP));
        }
        prior
    };

    // Step 3: write the prior mask back to user memory AFTER releasing the
    // lock, again to keep demand-paging recursion-safe.
    if oldset != 0 {
        let bytes = prior_mask.to_le_bytes();
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), oldset as *mut u8, 8);
        }
    }

    0
}

/// FUTEX_WAKE_GHOST emission counter — incremented every time the
/// `[FUTEX_WAKE_GHOST]` diagnostic fires.  Used by the in-kernel test
/// harness (Test 238) to assert the diagnostic is reachable without
/// having to grep the serial transcript from inside the kernel.  Compiled
/// under both `firefox-test` (where the diagnostic is exercised against
/// real userspace) and `test-mode` (where Test 238 drives it with a
/// synthetic waiter).  Both features are diagnostic-only configurations
/// and the 8-byte atomic has no cost on the default build.
#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
pub(crate) static FUTEX_WAKE_GHOST_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

// ═══════════════════════════════════════════════════════════════════════════════
// History-based FUTEX_WAKE_GHOST detection (BZ 25847 measurement)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The snapshot-based `[FUTEX_WAKE_GHOST]` diagnostic above only counts a
// "ghost wake" when a sibling waiter is parked AT THAT INSTANT inside the
// 256-byte cluster around the caller's uaddr.  This understates the
// glibc cond_var two-group cycling pattern: under that pattern, the
// signaller wakes group N while the prior waiter on group N-1 has already
// transitioned and been removed from the wait queue, so the snapshot lookup
// finds nothing even though the cycling structure is exactly the same as
// the literal-concurrent case.
//
// The history-based detector below records every FUTEX_WAIT entry in a
// bounded global ring buffer (uaddr, pid, tid, tick).  When a FUTEX_WAKE
// returns `woken=0`, the WAKE path scans the recent history (default
// window: 10 ticks ≈ 100 ms at 100 Hz) for any waiter on the same pid
// within ±128 bytes of the wake uaddr.  A hit increments the history-hits
// counter and bumps an offset-bucketed histogram, and a rate-limited
// `[FUTEX_WAKE_GHOST_HIST]` line is emitted.
//
// Per glibc BZ 25847 (cond_var __g_refs[2] dual-group bookkeeping):
//   https://sourceware.org/bugzilla/show_bug.cgi?id=25847
// The canonical __g_refs offsets inside `pthread_cond_t` are +0x50 and
// +0x54 (group-0 and group-1 ref counters).  A wake to one group while
// the prior generation's waiter was parked on the other group is the
// dominant signature of the BZ 25847 cycling pattern.
//
// Per futex(2): `FUTEX_WAKE returns the number of waiters that were woken
// up`; a return of 0 with no nearby waiter is legitimate (no thread was
// parked).  A return of 0 with a recent nearby waiter is the diagnostic of
// interest.  Per POSIX pthread_cond_signal(3p): `If no threads are blocked
// on the condition variable, then pthread_cond_signal() shall have no
// effect`.
//
// The ring is global (not per-process) — per the dispatch trade-off note,
// touching the Process struct for a ring field would surface across every
// init site; a global ring with TGID filtering at correlate-time keeps the
// patch localised and additive.  TGID filtering is cheap (one u64 compare
// per ring entry scanned, ≤ 256 entries per scan).
//
// Memory footprint: 256 entries × 32 bytes = 8 KB total (single
// allocation, owned by `FUTEX_WAIT_HISTORY`).  Lazy: the ring lives in
// kernel BSS and is only touched when the `firefox-test` or `test-mode`
// feature is enabled.  Zero overhead on the default build.

#[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
pub(crate) mod ghost_hist {
    //! History-based FUTEX_WAKE_GHOST detection helpers.
    //!
    //! Hooked into `sys_futex_linux` at two well-defined points so the
    //! diagnostic side is clearly separable from the FUTEX_WAKE decision
    //! path (so it does not conflict with the parallel BZ 25847
    //! broadcast-within-cluster compensation work):
    //!
    //!   - FUTEX_WAIT enqueue → `record_wait()`
    //!   - FUTEX_WAKE post-decision, when `woken == 0` → `correlate_wake()`
    //!
    //! Neither helper modifies the wake decision; they observe and report.
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Single history entry: a recorded FUTEX_WAIT call.
    ///
    /// `tick == 0` flags a slot as empty (un-occupied).  The first WAIT
    /// recorded always lands at tick ≥ 1 (assigned via `get_ticks()`),
    /// so 0 is a safe sentinel.
    #[derive(Clone, Copy)]
    pub struct WaitEntry {
        pub pid:   u64,
        pub tid:   u64,
        pub uaddr: u64,
        pub tick:  u64, // 0 = empty slot
    }

    impl WaitEntry {
        const EMPTY: WaitEntry = WaitEntry { pid: 0, tid: 0, uaddr: 0, tick: 0 };
    }

    /// Ring-buffer capacity.  256 entries × 32 B = 8 KB, sized to capture
    /// roughly the last 5–10 seconds of cond_var traffic at the rates we
    /// observe in Firefox under firefox-test.
    pub const HIST_CAPACITY: usize = 256;

    /// Correlation window in PIT ticks (100 Hz → 1 tick = 10 ms).
    /// 10 ticks = 100 ms, matching the "recent" window the dispatch
    /// brief specifies.  Wakes more than 100 ms after the last recorded
    /// matching wait are not counted.
    pub const HIST_WINDOW_TICKS: u64 = 10;

    /// Half-width of the cluster window in bytes.  Wake uaddr is matched
    /// against history entries within `[wake-128, wake+128]`.
    pub const HIST_CLUSTER_HALF: u64 = 128;

    /// Number of offset buckets in the histogram, indexed by
    /// `(offset / 4) + (HIST_CLUSTER_HALF/4)` for offsets in
    /// `[-HIST_CLUSTER_HALF, +HIST_CLUSTER_HALF)` rounded to 4 B
    /// granularity.  Plus one "other" bucket for anything outside the
    /// half-window or non-4 B-aligned.
    ///
    /// 64 + 1 buckets = 65 entries × 8 B = 520 B fixed BSS overhead.
    pub const N_OFFSET_BUCKETS: usize = 65;
    pub const OTHER_BUCKET: usize = N_OFFSET_BUCKETS - 1;

    /// Rate-limiting modulus for the per-event serial line.  One in
    /// every `HIST_HIT_PRINT_EVERY` history-hits prints a
    /// `[FUTEX_WAKE_GHOST_HIST]` line; the counters always update.
    /// 256 chosen so that a busy 10 k-wake trial emits ~40 lines —
    /// readable but not flooding.
    pub const HIST_HIT_PRINT_EVERY: u64 = 256;

    /// Global enable flag.  Default ON when `firefox-test` is enabled;
    /// can be toggled at runtime via `kdb futex set-ghost-hist on|off`.
    /// The default is OFF under `test-mode` alone so the in-kernel test
    /// suite does not accumulate history from the wider test corpus.
    #[cfg(feature = "firefox-test-core")]
    pub static GHOST_HIST_ENABLED: AtomicBool = AtomicBool::new(true);
    #[cfg(all(feature = "test-mode", not(feature = "firefox-test-core")))]
    pub static GHOST_HIST_ENABLED: AtomicBool = AtomicBool::new(false);

    /// Counts.
    pub static GHOST_HIST_TOTAL_WAKES: AtomicU64 = AtomicU64::new(0);
    pub static GHOST_HIST_WOKEN_ZERO: AtomicU64  = AtomicU64::new(0);
    pub static GHOST_HIST_HITS:       AtomicU64  = AtomicU64::new(0);
    pub static GHOST_HIST_WAITS:      AtomicU64  = AtomicU64::new(0);

    /// Per-offset histogram of correlated wake/wait distance, in 4 B
    /// buckets.  Bucket `i` (for i ∈ 0..64) corresponds to byte offset
    /// `(i as i64 - 32) * 4`.  Bucket 64 (`OTHER_BUCKET`) accumulates
    /// anything that doesn't fit (e.g. mis-aligned hits inside the
    /// half-window).  See `offset_to_bucket()`.
    pub static GHOST_HIST_OFFSET_COUNTS: [AtomicU64; N_OFFSET_BUCKETS] = {
        // Const-initialise an array of atomics.  `AtomicU64::new(0)` is
        // const-fn since Rust 1.41 so this works in `static` context.
        const Z: AtomicU64 = AtomicU64::new(0);
        [Z; N_OFFSET_BUCKETS]
    };

    /// History ring + write-cursor.  Holds the spinlock for O(1) writes
    /// and O(HIST_CAPACITY) reads.  Lock is held only for the duration
    /// of the ring access — no other kernel locks are taken inside
    /// (lookups against THREAD_TABLE or FUTEX_WAITERS happen outside
    /// this critical section, in the WAKE path that calls us).
    pub struct HistoryRing {
        pub entries: [WaitEntry; HIST_CAPACITY],
        pub next:    usize, // write cursor, wraps mod HIST_CAPACITY
    }

    impl HistoryRing {
        const fn new() -> Self {
            Self { entries: [WaitEntry::EMPTY; HIST_CAPACITY], next: 0 }
        }
    }

    pub static FUTEX_WAIT_HISTORY: spin::Mutex<HistoryRing> =
        spin::Mutex::new(HistoryRing::new());

    /// Map a (signed) byte offset to a histogram bucket index.
    /// Offsets in [-128, +124] rounded down to 4 B granularity map to
    /// buckets 0..64; anything outside or mis-aligned maps to
    /// `OTHER_BUCKET`.
    #[inline]
    pub fn offset_to_bucket(off: i64) -> usize {
        if off < -(HIST_CLUSTER_HALF as i64) || off >= HIST_CLUSTER_HALF as i64 {
            return OTHER_BUCKET;
        }
        if off % 4 != 0 { return OTHER_BUCKET; }
        // Centre bucket index at 32 so off=0 → bucket 32, off=-128 → 0,
        // off=+124 → 63.
        ((off / 4) + 32) as usize
    }

    /// Inverse of `offset_to_bucket` for printing.  Returns the byte
    /// offset corresponding to bucket `i`; `OTHER_BUCKET` returns 0
    /// (callers handle that bucket specially).
    #[inline]
    pub fn bucket_to_offset(i: usize) -> i64 {
        if i >= OTHER_BUCKET { return 0; }
        (i as i64 - 32) * 4
    }

    /// Record a FUTEX_WAIT enqueue in the history ring.  Called from
    /// the FUTEX_WAIT arm of `sys_futex_linux` immediately after the
    /// waiter has been enqueued + marked Blocked (so the ordering with
    /// the wake-side scan is clear: a wake racing us either sees us in
    /// FUTEX_WAITERS already or sees us in history within HIST_WINDOW_TICKS).
    ///
    /// No-op if `GHOST_HIST_ENABLED` is false.  Cheap (one atomic load
    /// + one mutex critical section bounded to O(1)).
    pub fn record_wait(pid: u64, tid: u64, uaddr: u64) {
        if !GHOST_HIST_ENABLED.load(Ordering::Relaxed) { return; }
        let tick = crate::arch::x86_64::irq::get_ticks().max(1);
        let mut ring = FUTEX_WAIT_HISTORY.lock();
        let idx = ring.next % HIST_CAPACITY;
        ring.entries[idx] = WaitEntry { pid, tid, uaddr, tick };
        ring.next = ring.next.wrapping_add(1);
        drop(ring);
        GHOST_HIST_WAITS.fetch_add(1, Ordering::Relaxed);
    }

    /// Correlate a `woken=0` FUTEX_WAKE against the per-process wait
    /// history.  Returns the number of distinct (pid, tid, uaddr)
    /// history entries within `[uaddr - HIST_CLUSTER_HALF, uaddr +
    /// HIST_CLUSTER_HALF)` whose recorded tick is within the last
    /// `HIST_WINDOW_TICKS` ticks of `now`.
    ///
    /// Also updates the offset histogram and the hit counter.  Emits a
    /// rate-limited `[FUTEX_WAKE_GHOST_HIST]` serial line per hit so a
    /// harness can grep it out.
    ///
    /// Returns 0 if `GHOST_HIST_ENABLED` is false.
    pub fn correlate_wake(pid: u64, wake_tid: u64, wake_uaddr: u64) -> u64 {
        if !GHOST_HIST_ENABLED.load(Ordering::Relaxed) { return 0; }
        let now = crate::arch::x86_64::irq::get_ticks();
        let cutoff = now.saturating_sub(HIST_WINDOW_TICKS);
        let lo = wake_uaddr.wrapping_sub(HIST_CLUSTER_HALF);
        let hi = wake_uaddr.wrapping_add(HIST_CLUSTER_HALF);

        let mut hits: u64 = 0;
        // Collect a small fixed-size sample of (offset, waiter_uaddr,
        // waiter_tid, age_ticks) tuples for the rate-limited line.
        // The full per-bucket histogram is updated unconditionally —
        // only the per-event print is sampled.
        let mut first_hit: Option<(i64, u64, u64, u64)> = None;

        let ring = FUTEX_WAIT_HISTORY.lock();
        for entry in ring.entries.iter() {
            if entry.tick == 0 { continue; }            // empty slot
            if entry.pid != pid { continue; }           // different process
            if entry.tick < cutoff { continue; }        // outside time window
            if entry.uaddr < lo || entry.uaddr >= hi { continue; } // outside cluster
            // Compute signed offset (waiter - wake).
            let off = entry.uaddr as i64 - wake_uaddr as i64;
            let bucket = offset_to_bucket(off);
            GHOST_HIST_OFFSET_COUNTS[bucket].fetch_add(1, Ordering::Relaxed);
            hits = hits.saturating_add(1);
            if first_hit.is_none() {
                let age = now.saturating_sub(entry.tick);
                first_hit = Some((off, entry.uaddr, entry.tid, age));
            }
        }
        drop(ring);

        if hits > 0 {
            let total_hits = GHOST_HIST_HITS.fetch_add(hits, Ordering::Relaxed)
                .saturating_add(hits);
            if let Some((off, waddr, wtid, age_ticks)) = first_hit {
                // Rate-limit the serial line: 1 in HIST_HIT_PRINT_EVERY.
                if total_hits % HIST_HIT_PRINT_EVERY == 0 || total_hits <= 4 {
                    let age_ms = age_ticks.saturating_mul(10); // 10 ms/tick
                    crate::serial_fast_println!(
                        "[FUTEX_WAKE_GHOST_HIST] tid={} tgid={} wake={:#x} \
                         waiter={:#x} waiter_tid={} offset={} age_ms={} \
                         woken_now=0 hits={}",
                        wake_tid, pid, wake_uaddr, waddr, wtid,
                        off, age_ms, hits
                    );
                }
            }
        }
        hits
    }

    /// Emit the `[GHOST_HIST_SUMMARY]` block.  Called at firefox-test
    /// exit (from `main.rs`) and from `kdb futex-ghost-hist` so an
    /// agent can request it on demand.
    ///
    /// Format intentionally matches the structured shape called out in
    /// the dispatch — the harness parses these lines line-by-line.
    pub fn dump_summary() {
        let total_wakes = GHOST_HIST_TOTAL_WAKES.load(Ordering::Relaxed);
        let woken_zero  = GHOST_HIST_WOKEN_ZERO.load(Ordering::Relaxed);
        let hits        = GHOST_HIST_HITS.load(Ordering::Relaxed);
        let waits       = GHOST_HIST_WAITS.load(Ordering::Relaxed);
        crate::serial_println!(
            "[GHOST_HIST_SUMMARY] total_wakes={} woken_zero={} hist_hits={} waits_recorded={}",
            total_wakes, woken_zero, hits, waits
        );
        // Per-offset histogram — emit non-zero buckets in order.
        let off_50  = offset_to_bucket(0x50);
        let off_54  = offset_to_bucket(0x54);
        let off_08  = offset_to_bucket(0x08);
        let off_04  = offset_to_bucket(0x04);
        let off_00  = offset_to_bucket(0x00);
        let off_n08 = offset_to_bucket(-0x08);
        let v_50  = GHOST_HIST_OFFSET_COUNTS[off_50].load(Ordering::Relaxed);
        let v_54  = GHOST_HIST_OFFSET_COUNTS[off_54].load(Ordering::Relaxed);
        let v_08  = GHOST_HIST_OFFSET_COUNTS[off_08].load(Ordering::Relaxed);
        let v_04  = GHOST_HIST_OFFSET_COUNTS[off_04].load(Ordering::Relaxed);
        let v_00  = GHOST_HIST_OFFSET_COUNTS[off_00].load(Ordering::Relaxed);
        let v_n08 = GHOST_HIST_OFFSET_COUNTS[off_n08].load(Ordering::Relaxed);
        let v_other = GHOST_HIST_OFFSET_COUNTS[OTHER_BUCKET].load(Ordering::Relaxed);
        // Sum all other named (non-canonical) buckets so the total
        // reconciles with hits.  Anything not surfaced as a named offset
        // is folded into v_named_other below.
        let mut v_named_other: u64 = 0;
        for (i, slot) in GHOST_HIST_OFFSET_COUNTS.iter().enumerate() {
            if i == off_50 || i == off_54 || i == off_08
            || i == off_04 || i == off_00 || i == off_n08
            || i == OTHER_BUCKET {
                continue;
            }
            v_named_other = v_named_other.saturating_add(
                slot.load(Ordering::Relaxed)
            );
        }
        crate::serial_println!(
            "  offset_+0x50={} (canonical __g_refs[0])", v_50);
        crate::serial_println!(
            "  offset_+0x54={} (canonical __g_refs[1])", v_54);
        crate::serial_println!("  offset_+0x08={}", v_08);
        crate::serial_println!("  offset_+0x04={}", v_04);
        crate::serial_println!("  offset_+0x00={}", v_00);
        crate::serial_println!("  offset_-0x08={}", v_n08);
        crate::serial_println!("  offset_other_aligned={}", v_named_other);
        crate::serial_println!("  offset_unaligned_or_out_of_range={}", v_other);
    }

    /// Clear all history-mode state.  Used by tests that need a clean
    /// baseline.  Holds the ring lock + zeroes the counters; cheap.
    pub fn reset_for_test() {
        let mut ring = FUTEX_WAIT_HISTORY.lock();
        for e in ring.entries.iter_mut() { *e = WaitEntry::EMPTY; }
        ring.next = 0;
        drop(ring);
        GHOST_HIST_TOTAL_WAKES.store(0, Ordering::Relaxed);
        GHOST_HIST_WOKEN_ZERO.store(0, Ordering::Relaxed);
        GHOST_HIST_HITS.store(0, Ordering::Relaxed);
        GHOST_HIST_WAITS.store(0, Ordering::Relaxed);
        for slot in GHOST_HIST_OFFSET_COUNTS.iter() {
            slot.store(0, Ordering::Relaxed);
        }
    }

    /// Runtime toggle.  Setting `false` quiesces the diagnostic without
    /// rebuilding the kernel — useful in long-running firefox-test runs
    /// where the test driver wants to compare with/without history-mode
    /// statistics on the same boot.
    pub fn set_enabled(on: bool) {
        GHOST_HIST_ENABLED.store(on, Ordering::Relaxed);
    }

    /// Returns the current enabled state, for kdb status reporting.
    pub fn is_enabled() -> bool {
        GHOST_HIST_ENABLED.load(Ordering::Relaxed)
    }
}

/// futex — Wait/Wake/Requeue implementation for musl/pthread compatibility.
///
/// Supported ops (op numbers per `futex(2)` Linux man-page and UAPI header):
///   0  FUTEX_WAIT          Block if *uaddr==val, optional timeout in arg4
///   1  FUTEX_WAKE          Wake up to val waiters on uaddr
///   3  FUTEX_REQUEUE       Wake val waiters on uaddr, requeue up-to val2 to uaddr2
///   4  FUTEX_CMP_REQUEUE   Like REQUEUE but atomically check *uaddr==val3 first
///   5  FUTEX_WAKE_OP       Not yet implemented — returns ENOSYS
///   9  FUTEX_WAIT_BITSET   Like WAIT (bitset arg accepted but treated as MATCH_ANY)
///  10  FUTEX_WAKE_BITSET   Like WAKE (bitset arg accepted but treated as MATCH_ANY)
///
/// Op-flags (per `futex(2)`):
///   0x80   FUTEX_PRIVATE_FLAG     — private to this process; treated as a hint
///   0x100  FUTEX_CLOCK_REALTIME   — `timeout_ptr` is an *absolute* CLOCK_REALTIME
///                                   timestamp (seconds + nanoseconds since epoch),
///                                   not a relative interval.  Required for glibc's
///                                   `pthread_cond_timedwait()` and any caller that
///                                   computes a deadline ahead of time.
///
/// `_val3` is the bitset for `FUTEX_WAIT_BITSET` / `FUTEX_WAKE_BITSET`, or `val3`
/// for `FUTEX_CMP_REQUEUE`.  We accept any non-zero bitset (including
/// `FUTEX_BITSET_MATCH_ANY = 0xFFFF_FFFF`) and currently ignore filtering — every
/// waker pairs with every waiter on the same uaddr, which matches glibc's actual
/// usage (cond impls always pass `MATCH_ANY`).
pub fn sys_futex_linux(
    uaddr: u64,
    futex_op: u64,
    val: u64,
    timeout_ptr: u64,
    uaddr2: u64,
    _val3: u64,
) -> i64 {
    const FUTEX_PRIVATE_FLAG:   u64 = 0x80;
    const FUTEX_CLOCK_REALTIME: u64 = 0x100;

    let op = futex_op & 0x7F; // Strip FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME
    let abs_realtime = (futex_op & FUTEX_CLOCK_REALTIME) != 0;
    let pid = crate::proc::current_pid_lockless();

    // Per `futex(2)` (FUTEX_PRIVATE_FLAG): when the caller sets the private
    // flag, the futex is process-private and keyed by `(mm, uaddr)` — the
    // fast path.  When it is clear, a futex word that lives on a `MAP_SHARED`
    // file/`memfd`-backed page is process-shared and must be keyed by its
    // backing-object identity so two processes mapping the same object at
    // different virtual addresses rendezvous (`resolve_futex_key`).  Mozilla's
    // cross-process screenshot rendezvous (`CrossProcessSemaphore` on a
    // `memfd` `MAP_SHARED` page) takes exactly this shared path: it does NOT
    // set FUTEX_PRIVATE_FLAG, the content process WAITs and the parent WAKEs
    // (or vice versa), and only a shared key lets the wake reach the waiter.
    let force_private = (futex_op & FUTEX_PRIVATE_FLAG) != 0;
    // The rendezvous key for ops that operate on `uaddr` (WAIT/WAKE/REQUEUE
    // source/WAKE_OP first wake).  Resolved once here (one VMA lookup on the
    // shared path; a no-op on the private fast path), then reused by every
    // bucket operation below so waiter and waker land in the same bucket.
    let key = crate::syscall::resolve_futex_key(pid, uaddr, force_private);
    // The destination key for the two-address ops (REQUEUE dst, WAKE_OP second
    // wake) is resolved lazily in those branches — `uaddr2` is unused (and may
    // be a non-pointer count) for the single-address ops.

    // Read the timespec at `timeout_ptr` (NULL means "no timeout") and convert
    // it to a *relative* nanosecond duration that the rest of the handler can
    // turn into a tick-based wake deadline.
    //
    // Per `futex(2)`, when `FUTEX_CLOCK_REALTIME` is set on the op (specifically
    // for FUTEX_WAIT_BITSET in mainline kernels, more permissively here), the
    // timespec is an *absolute* CLOCK_REALTIME timestamp — i.e. a wall-clock
    // deadline.  glibc's `pthread_cond_timedwait()` uses this exact form: it
    // computes `abstime = clock_gettime(CLOCK_REALTIME) + user_relative_timeout`
    // and passes the absolute value through.  If we treat that absolute value
    // as a relative interval, the kernel parks the caller for ~50,000 years
    // instead of the requested few milliseconds — observable as ETIMEDOUT
    // never firing on `pthread_cond_timedwait` (timeouts are silently swallowed,
    // event loops that depend on timed waits stall).
    //
    // Convert absolute → relative by subtracting "now" from the deadline.  If
    // the deadline has already elapsed, return None to signal "fire immediately"
    // up the call chain (caller will treat as ETIMEDOUT for FUTEX_WAIT).
    enum TimeoutNs {
        Indefinite,           // timeout_ptr was NULL
        Relative(u64),        // duration in nanoseconds
        AlreadyExpired,       // absolute deadline in the past
    }
    // Per futex(2): the `timeout` argument is only consulted for operations
    // that actually park the caller (WAIT, WAIT_BITSET, LOCK_PI, WAIT_REQUEUE_PI).
    // For wake-class ops (WAKE, WAKE_OP, WAKE_BITSET, REQUEUE, CMP_REQUEUE,
    // UNLOCK_PI, TRYLOCK_PI) the 4th syscall argument is reused as a count
    // or comparison value and MUST NOT be dereferenced as a pointer — musl's
    // pthread_cond_signal passes a non-zero non-pointer in this slot, so a
    // blanket dereference here faults on a small integer (e.g. 0x8).
    //
    // Mainline Linux uses the same gate: `kernel/futex/syscalls.c` only
    // calls `get_timespec64()` from the WAIT/LOCK_PI/WAIT_REQUEUE_PI paths,
    // never from the WAKE paths.  See futex(2) "TIMEOUTS".
    const FUTEX_OPS_WITH_TIMEOUT: [u64; 5] = [
        0,  // FUTEX_WAIT
        9,  // FUTEX_WAIT_BITSET
        6,  // FUTEX_LOCK_PI
        8,  // FUTEX_WAIT_REQUEUE_PI
        11, // FUTEX_LOCK_PI2
    ];
    let timeout_consumed_by_op = FUTEX_OPS_WITH_TIMEOUT.contains(&op);
    let timeout_ns = if timeout_ptr == 0 || !timeout_consumed_by_op {
        TimeoutNs::Indefinite
    } else {
        // Read the full timespec (tv_sec, tv_nsec) under ONE SMAP
        // bracket; the helper validates the 16-byte range internally
        // (one validate_user_ptr call vs the prior shape's three).
        let (tv_sec, tv_nsec) = match unsafe { crate::syscall::user_read_timespec(timeout_ptr) } {
            Some(t) => t,
            None => return -14, // EFAULT
        };
        if tv_nsec >= 1_000_000_000 {
            return -22; // EINVAL — out-of-range nanoseconds, per futex(2).
        }
        let raw_ns = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);

        if abs_realtime {
            // Convert absolute CLOCK_REALTIME deadline to a relative duration.
            // CLOCK_REALTIME advances at the monotonic tick rate from a
            // boot-time wall-clock anchor — the same formula as
            // `sys_clock_gettime(CLOCK_REALTIME)` and `__vdso_clock_gettime`.
            //
            // Per `man 2 futex` (FUTEX_CLOCK_REALTIME) and `man 2
            // clock_gettime`: the kernel's notion of "now" for an absolute
            // CLOCK_REALTIME deadline MUST agree with the value userspace
            // would read from `clock_gettime(CLOCK_REALTIME)`.  glibc's
            // `sem_timedwait` and `pthread_cond_timedwait` derive their
            // deadline from `clock_gettime(CLOCK_REALTIME)` (vDSO) and pass
            // the absolute timestamp back here; if the two formulas differ,
            // the deadline appears already-expired and ETIMEDOUT fires
            // immediately, breaking every timed wait.
            // TSC-derived ns for parity with __vdso_clock_gettime and
            // sys_clock_gettime — if these three formulas differ, an
            // absolute deadline computed via the vDSO can appear
            // already-expired here and fire ETIMEDOUT immediately.
            let mono_ns_total = crate::proc::vdso::monotonic_ns();
            let (mono_secs, sub_nsecs) = if mono_ns_total != 0 {
                (mono_ns_total / 1_000_000_000, mono_ns_total % 1_000_000_000)
            } else {
                let wall_ticks = crate::arch::x86_64::irq::get_ticks();
                (wall_ticks / 100, (wall_ticks % 100) * 10_000_000)
            };
            let now_secs = crate::proc::vdso::wall_secs_at_boot()
                .saturating_add(mono_secs);
            let now_ns = now_secs
                .saturating_mul(1_000_000_000)
                .saturating_add(sub_nsecs);
            if raw_ns <= now_ns {
                TimeoutNs::AlreadyExpired
            } else {
                TimeoutNs::Relative(raw_ns - now_ns)
            }
        } else {
            // Default WAIT semantics: timespec is a relative interval.
            TimeoutNs::Relative(raw_ns)
        }
    };

    match op {
        0 | 9 => {
            // FUTEX_WAIT / FUTEX_WAIT_BITSET: block if *uaddr == val.
            //
            // Lost-wakeup race fix (post-PR-#123 wedge): the value-vs-`val`
            // recheck and the wait-queue insertion MUST occur under the same
            // critical section as the FUTEX_WAKE-side queue scan, otherwise a
            // concurrent waker can race past an arriving waiter and observe
            // an empty queue, returning `woken=0` while the waiter then
            // enqueues itself with no wake on the way.
            //
            // Per `man 2 futex` (FUTEX_WAIT semantics):
            //   "If the thread starts to sleep, it is considered a waiter
            //    on this futex word.  If the futex value does not match val,
            //    then the call fails immediately with EAGAIN.  […]  The
            //    purpose of the comparison is to prevent lost wake-ups: if
            //    another thread changes the value of the futex word between
            //    the calling thread's load and the kernel's check that the
            //    thread should sleep, the kernel returns EAGAIN."
            //
            // The "kernel's check" must be inside the wait-queue critical
            // section — otherwise the lost-wakeup window the comparison is
            // meant to close is reopened by the kernel itself.  The matching
            // pattern in mainline Linux is `futex_wait_setup` in
            // `kernel/futex/waitwake.c`: the comparison-and-enqueue is one
            // critical section, gated by the futex hash bucket spinlock.
            //
            // Lock order: FUTEX_WAITERS → THREAD_TABLE.  We hold FUTEX_WAITERS
            // across the THREAD_TABLE acquire so that any concurrent
            // FUTEX_WAKE on the same key blocks on FUTEX_WAITERS until we
            // have both registered as a waiter and transitioned to Blocked.

            // Per `futex(2)`: an absolute CLOCK_REALTIME deadline that has
            // already passed must return ETIMEDOUT immediately, without
            // parking the caller.  Catch this before touching the wait queue
            // so we never end up with a registered-but-already-expired waiter.
            if matches!(timeout_ns, TimeoutNs::AlreadyExpired) {
                #[cfg(feature = "firefox-test-trace")]
                crate::serial_fast_println!(
                    "[FUTEX_TIMEDOUT] tid={} pid={} uaddr={:#x} op={:#x} (absolute deadline elapsed)",
                    crate::proc::current_tid(), pid, uaddr, futex_op
                );
                return -110; // ETIMEDOUT
            }

            // Validate the user pointer up front (cheap — no locks held).
            // Holding FUTEX_WAITERS across `user_read_u32` is otherwise
            // safe (no allocation, no further locks, no #PF handler that
            // would re-enter the futex queue), but failing fast on EFAULT
            // before touching the queue avoids a needless lock acquire.
            if !crate::syscall::validate_user_ptr(uaddr, 4) || (uaddr & 3) != 0 {
                return -14; // EFAULT
            }

            let tid = crate::proc::current_tid();

            // Compute the wake deadline (100 Hz tick → 10 ms per tick).
            let wake_tick = match timeout_ns {
                TimeoutNs::Relative(ns) => {
                    let now = crate::arch::x86_64::irq::get_ticks();
                    let delta_ticks = (ns / 10_000_000).max(1);
                    now.saturating_add(delta_ticks)
                }
                TimeoutNs::Indefinite => u64::MAX,
                TimeoutNs::AlreadyExpired => {
                    // Handled at function entry — keep defensive.
                    crate::arch::x86_64::irq::get_ticks()
                }
            };

            // ── Single critical section: check-then-queue under FUTEX_WAITERS ──
            //
            // The helper takes FUTEX_WAITERS, re-reads `*uaddr` under the
            // lock, compares to `val`, enqueues us on match, then takes
            // THREAD_TABLE (lock order: FUTEX_WAITERS → THREAD_TABLE) and
            // marks us Blocked.  Both locks are dropped on return; the
            // caller (us) invokes `schedule()` afterwards.
            //
            // A concurrent FUTEX_WAKE on the same key blocks on
            // FUTEX_WAITERS until we have both registered as a waiter and
            // transitioned to Blocked, so it cannot return `woken=0` while
            // we're still mid-registration.
            match crate::syscall::futex_wait_check_and_enqueue(
                key, val, tid, wake_tick,
                || unsafe { crate::syscall::user_read_u32(uaddr) },
            ) {
                crate::syscall::FutexWaitOutcome::Enqueued     => {}
                crate::syscall::FutexWaitOutcome::ValueMismatch => return -11, // EAGAIN
                crate::syscall::FutexWaitOutcome::Fault         => return -14, // EFAULT
            }

            // Record the waiter into the history-mode diagnostic ring.
            // This runs AFTER the waiter is enqueued + marked Blocked (so
            // the ring entry never names a TID that was never actually
            // parked) and BEFORE schedule(), so a concurrent wake
            // correlating against history during our sleep sees this
            // entry.  No-op if `ghost_hist::GHOST_HIST_ENABLED` is false.
            // See `ghost_hist::record_wait` for the BZ 25847 reference.
            #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
            ghost_hist::record_wait(pid, tid, uaddr);

            // ── Diagnostics live OUTSIDE the critical section ──────────────
            //
            // serial_println! is not free (UART MMIO + a Mutex on the writer)
            // and any ms it spends with the wait-queue lock held would widen
            // the race window the fix above is meant to close.  Emit the
            // [FUTEX_WAIT_REG] line and the rbp-chain walk now — the waiter
            // is already on the queue and Blocked, so a wake racing with
            // these prints is correct.
            #[cfg(feature = "firefox-test-trace")]
            {
                let user_rip = unsafe { crate::syscall::get_user_rip() };
                let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
                crate::serial_fast_println!(
                    "[FUTEX_WAIT_REG] tid={} pid={} uaddr={:#x} val={} op={:#x} \
                     rip={:#x} rsp={:#x} rbp={:#x}",
                    tid, pid, uaddr, val, futex_op, user_rip, user_rsp, user_rbp
                );
                if user_rbp != 0 && user_rsp < astryx_shared::KERNEL_VIRT_BASE {
                    let cr3 = crate::mm::vmm::get_cr3();
                    crate::syscall::ring::dump_futex_wait_stack(
                        tid, pid, uaddr, cr3, user_rip, user_rsp, user_rbp,
                    );
                }
            }

            // Gate-1 child-init probe (core profile): the socket/content
            // child's init-failure teardown is initiated by a synchronous
            // dispatch — a 1-byte self-pipe kick followed by THIS futex
            // wait.  A user backtrace at the wait names the posting call
            // path.  Bounded: child pids 2..=12 only, first 96 waits per
            // boot, so a steady-state boot emits nothing here.  GDB
            // user-VA breakpoints cannot arm cross-CR3, hence kernel-side.
            #[cfg(all(feature = "firefox-test-core",
                      not(feature = "firefox-test-trace")))]
            if (2..=12).contains(&pid) {
                use core::sync::atomic::{AtomicU32, Ordering};
                static GATE1_WALKS: AtomicU32 = AtomicU32::new(0);
                if GATE1_WALKS.fetch_add(1, Ordering::Relaxed) < 96 {
                    let user_rip = unsafe { crate::syscall::get_user_rip() };
                    let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
                    crate::serial_println!(
                        "[GATE1/FUTEX-WAIT] tid={} pid={} uaddr={:#x} val={} \
                         op={:#x} rip={:#x} rsp={:#x} rbp={:#x}",
                        tid, pid, uaddr, val, futex_op,
                        user_rip, user_rsp, user_rbp
                    );
                    if user_rsp < astryx_shared::KERNEL_VIRT_BASE {
                        let cr3 = crate::mm::vmm::get_cr3();
                        crate::syscall::ring::dump_futex_wait_stack(
                            tid, pid, uaddr, cr3, user_rip, user_rsp, user_rbp,
                        );
                        // Deep raw-stack window: 64 qwords above RSP so the
                        // offline symboliser can recover return addresses
                        // past the libc condwait frames (the 13-word scan in
                        // dump_futex_wait_scan stops short of the caller).
                        // Bounded by the same 96-walk cap as the line above.
                        let mut line = alloc::string::String::with_capacity(64 * 8);
                        let mut emitted = 0usize;
                        for i in 0..64u64 {
                            let va = user_rsp.wrapping_add(i * 8);
                            let v = crate::mm::vmm::virt_to_phys_in(cr3, va)
                                .map(|p| unsafe {
                                    core::ptr::read_volatile(
                                        (p + astryx_shared::KERNEL_VIRT_BASE) as *const u64)
                                });
                            if let Some(v) = v {
                                // Only candidate code pointers: canonical user
                                // VAs above 4 GiB (library text / heap range).
                                if v >= 0x1_0000_0000 && v < astryx_shared::KERNEL_VIRT_BASE {
                                    use core::fmt::Write as _;
                                    let _ = write!(line, " +{:#x}={:#x}", i * 8, v);
                                    emitted += 1;
                                    if emitted >= 24 { break; }
                                }
                            }
                        }
                        crate::serial_println!(
                            "[GATE1/STACKWIN] tid={} pid={} rsp={:#x}{}",
                            tid, pid, user_rsp, line);
                    }
                }
            }

            // Record this waiter in the per-CPU FUTEX_WAIT history ring so
            // the cluster-wake compensation (below) can use "this TGID
            // recently parked here" as a safety-harness signal when a
            // future FUTEX_WAKE on a nearby uaddr misses.
            #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
            crate::subsys::linux::futex_cluster::record_wait(pid, uaddr);

            crate::sched::schedule();

            // Woken (or timed out). Clean up from wait queue.
            //
            // A FUTEX_REQUEUE may have moved this TID off its original
            // `(pid, uaddr)` bucket into `(pid, uaddr2)` while it slept (per
            // `futex(2)`, requeue updates the waiter's queue key).  Scan the
            // bucket the waiter ACTUALLY sits in — the requeue destination if
            // one was recorded, else the original `uaddr` — so a
            // timeout-after-requeue removes the real orphan rather than
            // leaving a stale waiter in the uaddr2 bucket and misreporting the
            // timeout as a wake.
            let mut timed_out = false;
            {
                let mut waiters = crate::syscall::FUTEX_WAITERS.lock();
                // Consume any requeue destination recorded for this TID
                // (FUTEX_WAITERS → FUTEX_REQUEUE_DEST lock order, matching the
                // requeue insert).  `take`-style: remove it so the map does
                // not leak across this waiter's lifetime.
                let dest = crate::syscall::FUTEX_REQUEUE_DEST.lock().remove(&(pid, tid));
                // The bucket the waiter actually sits in: the requeue
                // destination key if a requeue moved it, else the key it
                // originally enqueued under.  Both are full FutexKeys, so a
                // shared-futex waiter (or one requeued onto a shared bucket) is
                // scanned in the right bucket.
                let cleanup_key = dest.unwrap_or(key);
                if let Some(list) = waiters.get_mut(&cleanup_key) {
                    let before = list.len();
                    list.retain(|&t| t != tid);
                    if list.len() < before { timed_out = true; } // still in list → timed out; already gone → woken
                    if list.is_empty() {
                        waiters.remove(&cleanup_key);
                    }
                }
            }
            // If we removed ourselves from the waiter list, the scheduler woke us = timeout.
            // If the list entry was already gone, FUTEX_WAKE removed us = success.
            if timed_out {
                #[cfg(feature = "firefox-test-trace")]
                crate::serial_fast_println!(
                    "[FUTEX_TIMEDOUT] tid={} pid={} uaddr={:#x} op={:#x}",
                    tid, pid, uaddr, futex_op
                );
                -110 // ETIMEDOUT
            } else {
                0
            }
        }
        1 | 10 => {
            // FUTEX_WAKE / FUTEX_WAKE_BITSET: wake up to val waiters
            let max_wake = if val == 0 { u64::MAX } else { val };
            let mut woken = 0u64;

            // Diagnostic: log every WAKE *attempt* on entry, even ones that
            // match nothing.  Combined with [FUTEX_WAKE] (post-match) and
            // [FUTEX_WAIT_REG] (registration), this lets the harness diff
            // attempted-wake uaddrs against still-parked uaddrs to decide
            // whether a missing-wakeup is "wake call never reached" vs
            // "wake call reached but wrong uaddr".  See the FUTEX_WAIT_REG
            // site for the fault-safety rationale of the user-frame helpers.
            #[cfg(feature = "firefox-test-trace")]
            {
                let user_rip = unsafe { crate::syscall::get_user_rip() };
                let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
                crate::serial_fast_println!(
                    "[FUTEX_WAKE_REQ] tid={} pid={} uaddr={:#x} max={} op={:#x} \
                     rip={:#x} rsp={:#x} rbp={:#x}",
                    crate::proc::current_tid(), pid, uaddr, val, futex_op,
                    user_rip, user_rsp, user_rbp
                );
            }

            let tids_to_wake: Vec<u64> = {
                let mut waiters = crate::syscall::FUTEX_WAITERS.lock();
                if let Some(list) = waiters.get_mut(&key) {
                    let mut result = Vec::new();
                    while !list.is_empty() && woken < max_wake {
                        result.push(list.remove(0));
                        woken += 1;
                    }
                    if list.is_empty() {
                        waiters.remove(&key);
                    }
                    result
                } else {
                    Vec::new()
                }
            };

            // Boost-and-ready each waiter + wakeup-preemption kick (shared
            // event-wake path; see `ipc::waitlist::wake_tids`).
            crate::ipc::waitlist::wake_tids(&tids_to_wake);

            // Diagnostic: every FUTEX_WAKE is a candidate root cause for a
            // missing-wakeup deadlock.  Logging the (uaddr, woken count, max
            // requested) triple lets the qemu-harness post-processor correlate
            // wakes against waiters by uaddr without having to instrument
            // userspace.  Gated to firefox-test to stay out of the test-mode
            // serial budget.
            #[cfg(feature = "firefox-test-trace")]
            crate::serial_fast_println!(
                "[FUTEX_WAKE] tid={} pid={} uaddr={:#x} woken={} max={} op={:#x}",
                crate::proc::current_tid(), pid, uaddr, woken, val, futex_op
            );

            // Futex-key resolution diagnostic: when this WAKE found zero
            // waiters at the exact key, emit the bucket landscape so the
            // harness can distinguish "kernel key correct, no waiter on
            // this logical futex" from "waiter and waker computed different
            // keys for what should be the same slot".  Observe-only.
            //
            // Per `futex(2)` (<https://man7.org/linux/man-pages/man2/futex.2.html>):
            // private-flag futexes are keyed `(mm, uaddr)`; AstryxOS uses
            // `(pid, uaddr)` (one mm per pid in this kernel), so a waiter
            // and waker on the same `pid` with identical `uaddr` MUST
            // hit the same bucket.  A populated `nearest=[…]` with the
            // waiter just a few bytes away from `uaddr` would indicate
            // the userspace producer signalled the wrong field of a
            // composite cond-var (musl `pthread_cond_t._c_seq` vs
            // `_c_waiters`, public layout in the musl source).
            #[cfg(feature = "firefox-test-trace")]
            if woken == 0 {
                crate::subsys::linux::futex_key_diag::emit_wake_empty(
                    pid, crate::proc::current_tid(), uaddr, futex_op,
                );
            }

            // Record this WAKE in the per-CPU history ring (regardless of
            // `woken`) so the cluster-wake compensation can use "this TID
            // recently issued a wake at this uaddr" as a safety-harness
            // signal on a subsequent ghost wake at a nearby slot.  Cheap
            // — bounded ring, ≤ 64 entries.
            #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
            crate::subsys::linux::futex_cluster::record_wake(
                crate::proc::current_tid(), uaddr,
            );

            // ── Bounded broadcast-within-cluster compensation ──────────
            //
            // When the original wake produced `woken == 0`, scan a 256-byte
            // window centred on `uaddr` and consider waking adjacent waiters
            // that pass the safety harness (canonical pthread_cond_t slot
            // offset OR same-TID recent wake / same-TGID recent wait).
            //
            // Per POSIX `pthread_cond_signal(3p)` (POSIX:2017 §2.9.5):
            // "If any threads are blocked on the condition variable, the
            // pthread_cond_signal() function shall unblock at least one of
            // those threads."  Older glibc condvar implementations race
            // between updating `__g_signals[g]` and parking on the matching
            // slot (public bug:
            // <https://sourceware.org/bugzilla/show_bug.cgi?id=25847>);
            // since we run upstream binaries unmodified, the recovery lives
            // here.
            //
            // The path is gated by a runtime toggle (default ON under
            // `firefox-test`, OFF in stock builds) and behind the same
            // feature gates as the GHOST diagnostic above.  See
            // `subsys/linux/futex_cluster.rs` for the full algorithm.
            #[cfg(any(feature = "firefox-test-core", feature = "test-mode"))]
            let extra_woken = if woken == 0 && (op == 1 || op == 10) {
                crate::subsys::linux::futex_cluster::compensate(
                    pid, crate::proc::current_tid(), uaddr, max_wake,
                )
            } else {
                0
            };
            #[cfg(not(any(feature = "firefox-test-core", feature = "test-mode")))]
            let extra_woken: u64 = 0;
            woken = woken.saturating_add(extra_woken);

            // [FUTEX_WAKE_GHOST] diagnostic — issued only when this WAKE
            // returned woken=0 yet another uaddr within the same 256-byte
            // cluster has parked waiters.  The shape is the typical "signal
            // posted to the wrong cond_var inside an enclosing object"
            // pattern: e.g. a Mozilla `Monitor` containing two
            // `pthread_cond_t` fields (each 48 bytes, so two fit in 256
            // bytes); the signaler updates and wakes field A while the
            // waiter is parked on field B.  Per POSIX
            // pthread_cond_signal(3p) "If no threads are blocked on the
            // condition variable, then pthread_cond_signal() shall have no
            // effect."  A genuine woken=0 with no nearby waiters is normal.
            // A woken=0 with nearby waiters is the diagnostic of interest.
            //
            // The cluster window is fixed at 256 bytes — wide enough to
            // span a small composite locking object holding multiple
            // condvar fields, narrow enough to avoid picking up unrelated
            // futexes in the same page.  Lookup is a bounded BTreeMap
            // range query; we hold FUTEX_WAITERS for the scan only, so the
            // critical section stays short.
            //
            // Compiled under `firefox-test` (the primary consumer — the
            // demo path drives this against real userspace) and under
            // `test-mode` (where Test 238 exercises it with a synthetic
            // waiter so the diagnostic can be verified deterministically
            // in CI).  The FUTEX_WAITERS scan and the per-event serial
            // output are diagnostic-only — the default build pays no
            // overhead.
            // Diagnostic GHOST scan (FUTEX_WAITERS lock + BTreeMap range scan +
            // [FUTEX_WAKE_GHOST] emit on every woken==0 wake).  Gated on the
            // trace features so the perf `firefox-test-core` boot pays neither
            // the per-wake scan nor the serial; `test-mode` keeps the full
            // behaviour so Test 238 (which asserts FUTEX_WAKE_GHOST_COUNT
            // advances) is unchanged.
            // The composite-cond-var GHOST cluster is a same-address-space
            // (PRIVATE-key) phenomenon — sibling pthread_cond_t fields within
            // one process's enclosing object.  A SHARED-key wake has no
            // `(pid, uaddr)` cluster to scan (its bucket identity is a backing
            // object, not a contiguous virtual range), so the diagnostic only
            // runs on the private path.
            #[cfg(any(feature = "firefox-test-trace", feature = "test-mode"))]
            if woken == 0 && (op == 1 || op == 10) {
                if let crate::syscall::FutexKey::Private(_, _) = key {
                const FUTEX_GHOST_CLUSTER: u64 = 256;
                let cluster_lo = uaddr & !(FUTEX_GHOST_CLUSTER - 1);
                let cluster_hi = cluster_lo + FUTEX_GHOST_CLUSTER;
                let waiters = crate::syscall::FUTEX_WAITERS.lock();
                // BTreeMap::range over the half-open [Private(pid, cluster_lo),
                // Private(pid, cluster_hi)) interval lets us find sibling
                // uaddrs in O(log n + k) without scanning the whole table.
                // Private(pid, _) keys for one pid are contiguous in the
                // FutexKey ordering (the Private variant sorts before Shared
                // and lexicographically by (pid, uaddr)).
                use crate::syscall::FutexKey;
                for (k, tids) in waiters
                    .range(FutexKey::Private(pid, cluster_lo)..FutexKey::Private(pid, cluster_hi))
                {
                    let (wpid, wuaddr) = match k {
                        FutexKey::Private(p, u) => (*p, *u),
                        FutexKey::Shared { .. } => continue,
                    };
                    if wpid != pid || wuaddr == uaddr { continue; }
                    if let Some(&first_tid) = tids.first() {
                        crate::serial_fast_println!(
                            "[FUTEX_WAKE_GHOST] tid={} pid={} caller_uaddr={:#x} \
                             sibling_uaddr={:#x} sibling_tid={} sibling_count={} \
                             cluster_lo={:#x} cluster_hi={:#x}",
                            crate::proc::current_tid(), pid, uaddr,
                            wuaddr, first_tid, tids.len(),
                            cluster_lo, cluster_hi
                        );
                        FUTEX_WAKE_GHOST_COUNT.fetch_add(
                            1, core::sync::atomic::Ordering::Relaxed
                        );
                    }
                }
                } // close: if let Private(_, _) = key
            }

            // History-mode GHOST correlation — observe-only.  This bumps
            // GHOST_HIST_TOTAL_WAKES on every FUTEX_WAKE/_BITSET and, for
            // the woken=0 subset, scans the per-process wait history for
            // any waiter on the same pid within ±128 bytes of the wake
            // uaddr that has been recorded within the last
            // HIST_WINDOW_TICKS ticks.  See the `ghost_hist` module for
            // the BZ 25847 framing.  The correlation does NOT modify
            // `woken`; the wake decision above is unchanged.  Gated on the
            // trace features (like the GHOST scan above) so the perf
            // `firefox-test-core` boot pays no per-wake counter/correlation
            // cost; `test-mode` keeps it so Test 240 is unchanged.
            #[cfg(any(feature = "firefox-test-trace", feature = "test-mode"))]
            if op == 1 || op == 10 {
                ghost_hist::GHOST_HIST_TOTAL_WAKES
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if woken == 0 {
                    ghost_hist::GHOST_HIST_WOKEN_ZERO
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    let _ = ghost_hist::correlate_wake(
                        pid, crate::proc::current_tid(), uaddr
                    );
                }
            }

            woken as i64
        }
        // FUTEX_REQUEUE (3) and FUTEX_CMP_REQUEUE (4) — per futex(2):
        //   arg1 = uaddr   (wait queue to drain)
        //   arg3 = val     (max threads to wake)
        //   arg4 = val2    (max threads to requeue; passed in the timeout_ptr slot)
        //   arg5 = uaddr2  (destination wait queue)
        //   arg6 = val3    (CMP_REQUEUE only: expected value at *uaddr)
        //
        // Return value: number of threads WOKEN (not woken+requeued).  Per
        // futex(2): "On success, FUTEX_REQUEUE returns the number of waiters
        // that were woken up."  The requeued count is not included.
        3 | 4 => {
            let val2 = timeout_ptr; // requeue limit (positional arg4 per futex(2) ABI)

            if op == 4 {
                // FUTEX_CMP_REQUEUE: atomically verify *uaddr == val3 before
                // proceeding.  Per futex(2): if *uaddr != val3, return EAGAIN.
                // `_val3` is arg6, the dedicated comparison value (distinct from
                // `val`, which is the wake count).
                let current = match unsafe { crate::syscall::user_read_u32(uaddr) } {
                    Some(v) => v,
                    None => return -14, // EFAULT
                };
                // Per futex(2), the futex word is 32-bit; compare only the low
                // 32 bits of `val3`.  The `val3` argument is typed `int` in the
                // C-library wrappers, so a value with bit 31 set arrives in the
                // 64-bit syscall register sign-extended (high half all-ones).
                // A full-width compare against the zero-extended 32-bit `*uaddr`
                // would mismatch in the high half and spuriously return EAGAIN,
                // breaking the pthread_cond broadcast/requeue handshake.
                if current != (_val3 as u32) {
                    return -11; // EAGAIN — *uaddr changed under us
                }
            }

            let max_wake = val;
            let max_requeue = val2;
            let mut woken = 0u64;
            let mut requeued = 0u64;

            // Destination rendezvous key for uaddr2.  Resolved with the same
            // `force_private` as the source — both addresses live in the same
            // address space and the private flag applies to the whole op.  A
            // requeue may legitimately move waiters between a private source
            // bucket and a shared destination bucket (or vice versa); keying
            // both correctly is what lets the requeued waiter be found later.
            let key2 = crate::syscall::resolve_futex_key(pid, uaddr2, force_private);

            let tids_to_wake: Vec<u64>;
            let tids_to_requeue: Vec<u64>;

            {
                let mut waiters = crate::syscall::FUTEX_WAITERS.lock();
                let src = waiters.remove(&key).unwrap_or_default();
                let mut wake_list = Vec::new();
                let mut requeue_list = Vec::new();
                for tid in src {
                    if woken < max_wake {
                        wake_list.push(tid);
                        woken += 1;
                    } else if requeued < max_requeue {
                        requeue_list.push(tid);
                        requeued += 1;
                    }
                }
                // Requeue surviving waiters to uaddr2's key.
                if !requeue_list.is_empty() {
                    waiters.entry(key2).or_insert_with(Vec::new).extend(requeue_list.iter());
                    // Record each requeued TID's new destination key so its
                    // own FUTEX_WAIT post-`schedule()` cleanup scans the
                    // bucket it now sits in (`key2`) rather than its original
                    // `key`.  Per `futex(2)`, requeue updates the waiter's
                    // queue key to uaddr2; without this a timeout-after-requeue
                    // would leave an orphan in the destination bucket and
                    // misreport ETIMEDOUT as success.  Taken while still
                    // holding FUTEX_WAITERS to keep the single FUTEX_WAITERS →
                    // FUTEX_REQUEUE_DEST lock order.
                    let mut dest = crate::syscall::FUTEX_REQUEUE_DEST.lock();
                    for &tid in &requeue_list {
                        dest.insert((pid, tid), key2);
                    }
                }
                tids_to_wake = wake_list;
                tids_to_requeue = requeue_list;
                let _ = tids_to_requeue; // live in the waiters map; used above
            }

            // Boost-and-ready each waiter + wakeup-preemption kick (shared
            // event-wake path; see `ipc::waitlist::wake_tids`).
            crate::ipc::waitlist::wake_tids(&tids_to_wake);

            // Return woken count only — not woken+requeued.  Per futex(2).
            woken as i64
        }
        // FUTEX_WAKE_OP (5) — compound atomic-modify-then-conditional-wake.
        // Per futex(2):
        //   1. Atomically apply OP(oparg) to *uaddr2, capturing the OLD value.
        //   2. Wake up to `val` (nr_wake) waiters on uaddr.
        //   3. If CMP(oldval, cmparg) is true, additionally wake up to `val2`
        //      (nr_wake2) waiters on uaddr2.
        //   Return total number of waiters woken (uaddr + uaddr2).
        //
        // The 32-bit `val3` (arg6) encodes the operation:
        //   bits 28..30  OP        (SET=0, ADD=1, OR=2, ANDN=3, XOR=4)
        //   bit  31      OPARG_SHIFT — interpret oparg as `1 << oparg`
        //   bits 24..27  CMP       (EQ=0, NE=1, LT=2, LE=3, GT=4, GE=5)
        //   bits 12..23  oparg     (signed 12-bit)
        //   bits  0..11  cmparg    (signed 12-bit)
        // glibc/musl use this for pthread_cond / barrier fast paths.
        5 => {
            let encoded_op = (_val3 & 0xFFFF_FFFF) as u32;
            let val2 = timeout_ptr; // nr_wake2 (positional arg4 per futex(2))

            // ── Decode the encoded operation ──────────────────────────────
            let op_field   = (encoded_op >> 28) & 0x7;
            let oparg_shift = (encoded_op & (0x8 << 28)) != 0;
            let cmp_field  = (encoded_op >> 24) & 0xF;
            // Sign-extend the two 12-bit fields to i32.
            let sext12 = |v: u32| -> i32 {
                let v = (v & 0xFFF) as i32;
                if v & 0x800 != 0 { v - 0x1000 } else { v }
            };
            let mut oparg = sext12((encoded_op >> 12) & 0xFFF);
            let cmparg    = sext12(encoded_op & 0xFFF);

            if oparg_shift {
                // `1 << oparg`; per futex(2) an oparg outside 0..=31 is a
                // program bug.  Linux masks it to 31 and continues rather than
                // erroring; we mirror that (mask, no fault) so a buggy caller
                // does not wedge.
                if !(0..=31).contains(&oparg) {
                    oparg &= 31;
                }
                oparg = 1i32 << (oparg & 31);
            }

            // Resolve uaddr2's rendezvous key BEFORE taking FUTEX_WAITERS:
            // `resolve_futex_key` acquires PROCESS_TABLE, and the established
            // lock order is FUTEX_WAITERS → THREAD_TABLE (never FUTEX_WAITERS →
            // PROCESS_TABLE).  Resolving up front keeps the critical section
            // below lock-clean.
            let key2 = crate::syscall::resolve_futex_key(pid, uaddr2, force_private);

            // ── Atomic modify of *uaddr2, capturing the old value ─────────
            // Read-modify-write is serialised by the FUTEX_WAITERS lock held
            // across the whole op: every wake-class futex op takes it, so no
            // concurrent futex modify of this word interleaves.  (A racing
            // *non-futex* userspace store can still interleave — but that is
            // true on real hardware too; futex(2) only guarantees atomicity
            // against other futex operations.)
            let mut waiters = crate::syscall::FUTEX_WAITERS.lock();

            let oldval = match unsafe { crate::syscall::user_read_u32(uaddr2) } {
                Some(v) => v as i32,
                None => return -14, // EFAULT — *uaddr2 unreadable
            };
            let newval: i32 = match op_field {
                0 => oparg,             // FUTEX_OP_SET
                1 => oldval.wrapping_add(oparg), // FUTEX_OP_ADD
                2 => oldval | oparg,    // FUTEX_OP_OR
                3 => oldval & !oparg,   // FUTEX_OP_ANDN
                4 => oldval ^ oparg,    // FUTEX_OP_XOR
                _ => return -22,        // EINVAL — unknown OP
            };
            // Store the new value into *uaddr2 in the caller's own address
            // space (symmetric with the user_read_u32 above).
            if !unsafe { crate::syscall::user_write_u32(uaddr2, newval as u32) } {
                return -14; // EFAULT — *uaddr2 unwritable
            }

            // ── Wake up to `val` waiters on uaddr ─────────────────────────
            let max_wake1 = if val == 0 { u64::MAX } else { val };
            let mut tids_to_wake: Vec<u64> = Vec::new();
            if let Some(list) = waiters.get_mut(&key) {
                let mut n = 0u64;
                while !list.is_empty() && n < max_wake1 {
                    tids_to_wake.push(list.remove(0));
                    n += 1;
                }
                if list.is_empty() { waiters.remove(&key); }
            }

            // ── Evaluate CMP(oldval, cmparg); if true wake uaddr2 too ─────
            let cmp_true = match cmp_field {
                0 => oldval == cmparg, // FUTEX_OP_CMP_EQ
                1 => oldval != cmparg, // FUTEX_OP_CMP_NE
                2 => oldval <  cmparg, // FUTEX_OP_CMP_LT
                3 => oldval <= cmparg, // FUTEX_OP_CMP_LE
                4 => oldval >  cmparg, // FUTEX_OP_CMP_GT
                5 => oldval >= cmparg, // FUTEX_OP_CMP_GE
                _ => return -22,       // EINVAL — unknown CMP
            };
            if cmp_true {
                let max_wake2 = if val2 == 0 { u64::MAX } else { val2 };
                if let Some(list) = waiters.get_mut(&key2) {
                    let mut n = 0u64;
                    while !list.is_empty() && n < max_wake2 {
                        tids_to_wake.push(list.remove(0));
                        n += 1;
                    }
                    if list.is_empty() { waiters.remove(&key2); }
                }
            }
            drop(waiters);

            // Flip every drained TID Blocked → Ready under one THREAD_TABLE
            // acquisition (same post-drain pattern as FUTEX_WAKE), with the
            // shared boost + wakeup-preemption kick.
            crate::ipc::waitlist::wake_tids(&tids_to_wake);

            tids_to_wake.len() as i64
        }
        _ => -38, // ENOSYS
    }
}

// ── Phase 6 syscall implementations ────────────────────────────────────────

/// eventfd(initval) / eventfd2(initval, flags) — Create a counter-based signaling fd.
///
/// `flags` may contain EFD_NONBLOCK (0x800), EFD_CLOEXEC (0x80000), EFD_SEMAPHORE (0x1).
/// The eventfd fd always returns EAGAIN when the counter is 0; EFD_NONBLOCK only matters
/// for callers using blocking semantics (which we don't yet implement as a sleep).
fn sys_eventfd_linux(initval: u64, flags: u32) -> i64 {
    let efd_id = crate::ipc::eventfd::create(initval, flags);
    if efd_id == u64::MAX {
        return -24; // EMFILE
    }

    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => {
            crate::ipc::eventfd::close(efd_id);
            return -3;
        }
    };

    // EFD_CLOEXEC = 0x80000, EFD_NONBLOCK = 0x800
    let efd_cloexec  = (flags & 0x0008_0000) != 0;
    let efd_nonblock = (flags & 0x0000_0800) != 0;
    let fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode:     efd_id,
        offset:    0,
        // Store nonblock flag in lower bits so poll/read can check it.
        flags:     0x0001_0000 | if efd_nonblock { 0x0800 } else { 0 },
        is_console: false,
        cloexec:   efd_cloexec,
        file_type: crate::vfs::FileType::EventFd,
        open_path: alloc::string::String::new(),
    };

    // Find a free slot.
    let mut slot = None;
    for (i, f) in proc.file_descriptors.iter().enumerate() {
        if f.is_none() { slot = Some(i); break; }
    }
    let idx = if let Some(i) = slot {
        i
    } else if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let i = proc.file_descriptors.len();
        proc.file_descriptors.push(None);
        i
    } else {
        crate::ipc::eventfd::close(efd_id);
        return -24; // EMFILE
    };

    proc.file_descriptors[idx] = Some(fd);
    idx as i64
}

/// pipe2(pipefd[2], flags) — Create a pipe with optional flags.
///
/// flags may include:
///   O_CLOEXEC (0x0008_0000) — set close-on-exec (stored but not enforced yet)
///   O_NONBLOCK (0x0800)     — set non-blocking (stored but not enforced yet)
fn sys_pipe2_linux(fds_out: *mut u32, flags: u32) -> i64 {
    if fds_out.is_null() {
        return -22; // EINVAL
    }

    let pipe_id = crate::ipc::pipe::create_pipe();
    let pid = crate::proc::current_pid_lockless();

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };

    let extra_flags: u32 = flags & (0x0008_0000 | 0x0800); // cloexec | nonblock

    let pipe_cloexec = (extra_flags & 0x0008_0000) != 0;
    let read_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode:     pipe_id,
        offset:    0,
        flags:     0x8000_0000 | extra_flags, // read end
        is_console: false,
        cloexec:   pipe_cloexec,
        file_type: crate::vfs::FileType::Pipe,
        open_path: alloc::string::String::new(),
    };
    let write_fd = crate::vfs::FileDescriptor {
        mount_idx: usize::MAX,
        inode:     pipe_id,
        offset:    0,
        flags:     0x8000_0001 | extra_flags, // write end
        is_console: false,
        cloexec:   pipe_cloexec,
        file_type: crate::vfs::FileType::Pipe,
        open_path: alloc::string::String::new(),
    };

    let mut read_idx  = None;
    let mut write_idx = None;
    for (i, f) in proc.file_descriptors.iter().enumerate() {
        if f.is_none() {
            if read_idx.is_none()       { read_idx  = Some(i); }
            else if write_idx.is_none() { write_idx = Some(i); break; }
        }
    }

    // Extend fd table if needed
    let ri = if let Some(i) = read_idx {
        i
    } else if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let i = proc.file_descriptors.len();
        proc.file_descriptors.push(None);
        i
    } else {
        return -24; // EMFILE
    };
    let wi = if let Some(i) = write_idx {
        i
    } else if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let i = proc.file_descriptors.len();
        proc.file_descriptors.push(None);
        i
    } else {
        return -24; // EMFILE
    };

    proc.file_descriptors[ri] = Some(read_fd);
    proc.file_descriptors[wi] = Some(write_fd);

    crate::serial_println!("[PIPE2] pid={} read_fd={} write_fd={} flags={:#x}", pid, ri, wi, flags);

    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::ptr::write_unaligned(fds_out,          ri as u32);
        core::ptr::write_unaligned(fds_out.add(1),   wi as u32);
    }
    0
}

/// statfs(path, buf) — Report filesystem statistics.
///
/// struct statfs (120 bytes on x86_64):
///   u64 f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree
///   u32[2] f_fsid
///   u64 f_namelen, f_frsize, f_flags
///   u64[4] f_spare
fn sys_statfs_linux(path_ptr: u64, buf: *mut u8) -> i64 {
    if buf.is_null() { return -14; }
    let path_raw = read_cstring_from_user(path_ptr);
    let path = core::str::from_utf8(&path_raw).unwrap_or("");

    // Check the path exists (ignore error — statfs on /proc etc. always ok).
    let _ = crate::vfs::stat(path);

    fill_statfs_buf(buf);
    0
}

/// fstatfs(fd, buf) — filesystem statistics for an open fd.
fn sys_fstatfs_linux(_fd: usize, buf: *mut u8) -> i64 {
    if buf.is_null() { return -14; }
    fill_statfs_buf(buf);
    0
}

/// Write a plausible statfs structure into `buf` (120 bytes).
fn fill_statfs_buf(buf: *mut u8) {
    // Wipe first.
    #[cfg(feature = "firefox-test-core")]
    crate::mm::w215_diag::probe(crate::mm::w215_diag::Writer::Preadv120, buf, 120);
    // SMAP bracket — `buf` is a user-VA pointer.
    let _g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    unsafe { core::ptr::write_bytes(buf, 0, 120); }
    // Use EXT2_SUPER_MAGIC (0xEF53) as f_type — widely recognised.
    let p = buf as *mut u64;
    unsafe {
        *p.add(0)  = 0xEF53;   // f_type
        *p.add(1)  = 4096;     // f_bsize
        *p.add(2)  = 1024*128; // f_blocks (~512 MiB)
        *p.add(3)  = 1024*64;  // f_bfree
        *p.add(4)  = 1024*64;  // f_bavail
        *p.add(5)  = 32768;    // f_files
        *p.add(6)  = 32768;    // f_ffree
        // f_fsid at offset 56 — leave 0
        // f_namelen at byte 64 = index 8 of u64 array
        *p.add(8)  = 255;      // f_namelen
        *p.add(9)  = 4096;     // f_frsize
        *p.add(10) = 0;        // f_flags (ST_RDONLY=1? leave 0 = rw)
    }
}

/// Regenerate /proc/self/maps for `pid` from the process's live VMA list.
///
/// memfd_create(name, flags) — create an anonymous in-memory file.
///
/// Per memfd_create(2): returns a new file descriptor backed by an
/// anonymous tmpfs file.  The file is automatically unlinked; it exists
/// only as long as the fd (and any dups) remain open.
///
/// Flags (from <linux/memfd.h>):
///   MFD_CLOEXEC       (0x0001) — set FD_CLOEXEC on the returned fd.
///   MFD_ALLOW_SEALING (0x0002) — enable fcntl F_ADD_SEALS / F_GET_SEALS.
///   MFD_HUGETLB       (0x0004) — backed by huge pages; not supported here.
fn sys_memfd_create(_name: u64, flags: u64) -> i64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static MEMFD_COUNTER: AtomicU64 = AtomicU64::new(0);

    // MFD flag constants per memfd_create(2).
    const MFD_CLOEXEC:       u64 = 0x0001;
    const MFD_ALLOW_SEALING: u64 = 0x0002;
    const MFD_HUGETLB:       u64 = 0x0004;
    // Huge-page size tags occupy bits 26–31; reserved but not enforced here.
    const MFD_HUGETLB_SIZE_MASK: u64 = 0xFC00_0000;
    const MFD_VALID_FLAGS: u64 =
        MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_HUGETLB_SIZE_MASK;

    // Reject unknown flags per memfd_create(2).
    if flags & !MFD_VALID_FLAGS != 0 {
        return -22; // EINVAL
    }
    // MFD_HUGETLB is not supported on this kernel configuration.
    if flags & MFD_HUGETLB != 0 {
        return -22; // EINVAL — HUGETLB not supported
    }

    let seq = MEMFD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = crate::proc::current_pid_lockless();

    // Build path /tmp/.memfd_NNNN
    let mut path_buf = [0u8; 32];
    let prefix = b"/tmp/.memfd_";
    path_buf[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();
    let mut n = seq;
    let mut digits = [0u8; 20];
    let mut dlen = 0usize;
    if n == 0 { digits[0] = b'0'; dlen = 1; }
    while n > 0 { digits[dlen] = b'0' + (n % 10) as u8; dlen += 1; n /= 10; }
    for i in (0..dlen).rev() { path_buf[pos] = digits[i]; pos += 1; }
    let path_str = core::str::from_utf8(&path_buf[..pos]).unwrap_or("/tmp/.memfd_0");

    // Create the backing file in VFS
    if crate::vfs::create_file(path_str).is_err() {
        return -28; // ENOSPC
    }

    // Open flags: always O_RDWR; honour MFD_CLOEXEC per memfd_create(2).
    let open_flags = crate::vfs::flags::O_RDWR
        | if flags & MFD_CLOEXEC != 0 { 0x0008_0000u32 } else { 0 }; // 0x80000 = O_CLOEXEC

    let fd_num = match crate::vfs::open(pid, path_str, open_flags) {
        Ok(n) => n,
        Err(_) => return -12, // ENOMEM
    };

    // Resolve the inode for this fd so we can register sealing capability.
    if flags & MFD_ALLOW_SEALING != 0 {
        let inode_opt = {
            let procs = crate::proc::PROCESS_TABLE.lock();
            procs.iter().find(|p| p.pid == pid).and_then(|p| {
                p.file_descriptors.get(fd_num).and_then(|f| f.as_ref()).map(|f| f.inode)
            })
        };
        if let Some(inode) = inode_opt {
            memfd_seals_register(inode);
        }
    }

    // Per memfd_create(2): "The file is automatically removed (unlinked) ...
    // The memory is freed when all references to the file are dropped."  Unlink
    // the backing entry now so the memfd is a true anonymous inode with no
    // visible name; the open fd (and any dup / fork / SCM_RIGHTS-passed copy)
    // holds it alive via the kernel's unlink-on-last-close machinery, and it is
    // freed once the last reference closes.  This makes a memfd handed between
    // processes (the Mozilla shared-memory / CrossProcessPaint surface fd) safe
    // *by construction* — the inode cannot outlive its last holder and leak,
    // nor be freed while an SCM_RIGHTS-passed copy is in flight (PINNED_INODES).
    // remove() on an open file performs a deferred delete, so the just-opened
    // fd stays fully usable.
    let _ = crate::vfs::remove(path_str);

    fd_num as i64
}

/// Test shim: call sys_memfd_create from in-kernel tests.
///
/// `_name` is unused (name is cosmetic); `flags` is the MFD_* flag word.
#[cfg(feature = "test-mode")]
pub fn sys_memfd_create_test(_name: u64, flags: u64) -> i64 {
    sys_memfd_create(_name, flags)
}

/// Test shim: call sys_fcntl from in-kernel tests.
#[cfg(feature = "test-mode")]
pub fn sys_fcntl_test(fd: u64, cmd: u64, arg: u64) -> i64 {
    sys_fcntl(fd, cmd, arg)
}

/// Test shim: close an fd from in-kernel tests (delegates to the shared close helper).
#[cfg(feature = "test-mode")]
pub fn sys_close_test(fd: u64) -> i64 {
    crate::syscall::sys_close_test(fd as usize)
}

/// Generate and write /proc/self/status for `pid` with live process data.
fn refresh_proc_status(pid: u64) {
    use alloc::string::String;

    // Snapshot the fields we need while holding the lock briefly.
    let (ppid, name_bytes, fd_count, vm_rss_kb) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            let ppid = p.parent_pid;
            let name_end = p.name.iter().position(|&b| b == 0).unwrap_or(8);
            let name_bytes = p.name[..name_end].to_vec();
            let fd_count = p.file_descriptors.iter().filter(|f| f.is_some()).count();
            // Estimate VmRSS from VMA list sizes.
            let vm_rss_kb: u64 = p.vm_space.as_ref()
                .map(|vs| vs.areas.iter().map(|a| a.length / 1024).sum())
                .unwrap_or(4096);
            (ppid, name_bytes, fd_count, vm_rss_kb)
        } else {
            return;
        }
    };

    let name_str = core::str::from_utf8(&name_bytes).unwrap_or("astryx");
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

    macro_rules! emit {
        ($($arg:tt)*) => {{
            use core::fmt::Write;
            let mut s = String::new();
            let _ = write!(s, $($arg)*);
            out.extend_from_slice(s.as_bytes());
        }};
    }

    emit!("Name:\t{}\n", name_str);
    emit!("State:\tR (running)\n");
    emit!("Tgid:\t{}\n", pid);
    emit!("Pid:\t{}\n", pid);
    emit!("PPid:\t{}\n", ppid);
    emit!("TracerPid:\t0\n");
    emit!("Uid:\t0\t0\t0\t0\n");
    emit!("Gid:\t0\t0\t0\t0\n");
    emit!("FDSize:\t{}\n", fd_count.next_power_of_two().max(256));
    emit!("Groups:\n");
    emit!("VmPeak:\t{} kB\n", vm_rss_kb);
    emit!("VmSize:\t{} kB\n", vm_rss_kb);
    emit!("VmLck:\t0 kB\n");
    emit!("VmRSS:\t{} kB\n", vm_rss_kb);
    emit!("VmData:\t{} kB\n", vm_rss_kb / 2);
    emit!("VmStk:\t128 kB\n");
    emit!("VmExe:\t0 kB\n");
    emit!("VmLib:\t0 kB\n");
    emit!("VmPTE:\t0 kB\n");
    emit!("Threads:\t1\n");
    emit!("SigPnd:\t0000000000000000\n");
    emit!("ShdPnd:\t0000000000000000\n");
    emit!("SigBlk:\t0000000000000000\n");
    emit!("SigIgn:\t0000000000000000\n");
    emit!("SigCgt:\t0000000000000000\n");
    emit!("CapInh:\t0000000000000000\n");
    emit!("CapPrm:\t0000003fffffffff\n");
    emit!("CapEff:\t0000003fffffffff\n");
    emit!("CapBnd:\t0000003fffffffff\n");
    emit!("CapAmb:\t0000000000000000\n");
    emit!("Cpus_allowed:\t1\n");
    emit!("Cpus_allowed_list:\t0\n");
    emit!("voluntary_ctxt_switches:\t0\n");
    emit!("nonvoluntary_ctxt_switches:\t0\n");

    let _ = crate::vfs::write_file("/proc/self/status", &out);
}

/// This is called every time a process opens /proc/self/maps so the content
/// always reflects the current address space.  We snapshot the VMA list while
/// holding PROCESS_TABLE, release the lock, then format + write the VFS file.
fn refresh_proc_maps(pid: u64) {
    use crate::mm::vma::{VmProt, PROT_READ, PROT_WRITE, PROT_EXEC};

    // Snapshot VMA data (base, end, prot, name) without holding any lock while
    // we format and write the VFS file (which acquires its own locks).
    struct VmaSnap {
        base: u64,
        end:  u64,
        prot: VmProt,
        name: &'static str,
    }

    let snaps: Vec<VmaSnap> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            if let Some(ref vs) = p.vm_space {
                vs.areas.iter().map(|a| VmaSnap {
                    base: a.base,
                    end:  a.end(),
                    prot: a.prot,
                    name: a.name,
                }).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    if snaps.is_empty() {
        return;
    }

    // Format each VMA entry.  Linux /proc/maps format:
    //   aaaa-bbbb rwxp 00000000 00:00 0 pathname\n
    let mut out = Vec::new();
    for s in &snaps {
        let r = if s.prot & PROT_READ  != 0 { b'r' } else { b'-' };
        let w = if s.prot & PROT_WRITE != 0 { b'w' } else { b'-' };
        let x = if s.prot & PROT_EXEC  != 0 { b'x' } else { b'-' };
        // Write base address
        write_hex64(&mut out, s.base);
        out.push(b'-');
        write_hex64(&mut out, s.end);
        out.push(b' ');
        out.push(r); out.push(w); out.push(x); out.push(b'p');
        // offset dev ino
        out.extend_from_slice(b" 00000000 00:00 0");
        if !s.name.is_empty() {
            out.push(b' ');
            out.push(b' ');
            out.extend_from_slice(s.name.as_bytes());
        }
        out.push(b'\n');
    }

    let _ = crate::vfs::write_file("/proc/self/maps", &out);
}

/// Write a 64-bit value as 16 lowercase hex digits into a Vec<u8>.
fn write_hex64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        let nibble = (v & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        v >>= 4;
    }
    out.extend_from_slice(&buf);
}

// ─── epoll helpers ───────────────────────────────────────────────────────────

/// Determine the current ready event mask for fd `fd` in process `pid`.
///
/// Rules:
///  - fd 0 (stdin):        0 (no interactive keyboard in test mode)
///  - fd 1/2 (stdout/err): EPOLLOUT
///  - pipe read-end:       EPOLLIN if data available
///  - pipe write-end:      EPOLLOUT always
///  - regular file/dir:    EPOLLIN | EPOLLOUT
///  - closed/invalid:      EPOLLERR
/// Poll the readiness events for `fd` in process `pid`.
/// Returns a bitmask of EPOLL* flags that are currently set.
pub(crate) fn epoll_poll_events(pid: u64, fd: usize) -> u32 {
    use crate::ipc::epoll::{EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, EPOLLRDHUP};

    // Snapshot fd metadata with a brief lock hold.  `mount_idx == usize::MAX`
    // together with the SOCKET_FD bit (`0x4000_0000`) in `flags` identifies a
    // socket fd; the UNIX_SOCKET_FLAG bit (`0x0080_0000`) disambiguates
    // AF_UNIX from AF_INET/AF_INET6 — matching `is_socket_fd` /
    // `is_unix_socket_fd` in `crate::syscall`.
    let info: Option<(u64, u32, bool, bool, crate::vfs::FileType, usize)> = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        procs.iter().find(|p| p.pid == pid).and_then(|proc| {
            proc.file_descriptors.get(fd)?.as_ref().map(|f| {
                let is_epoll = f.open_path.as_str() == "[epoll]";
                (f.inode, f.flags, f.is_console, is_epoll, f.file_type, f.mount_idx)
            })
        })
    };

    const SOCKET_FD_BIT:  u32 = 0x4000_0000;
    const UNIX_SOCK_BIT:  u32 = 0x0080_0000;
    const PIPE_FD_BIT:    u32 = 0x8000_0000;
    const O_WRONLY_BIT:   u32 = 0x01;

    match info {
        None => match fd { 0 => 0, 1 | 2 => EPOLLOUT, _ => EPOLLERR },
        Some((_, _, _, true, _, _)) => 0,
        Some((_, _, true, _, _, _)) => EPOLLOUT,
        Some((inode, _flags, false, false, crate::vfs::FileType::EventFd, _)) => {
            if crate::ipc::eventfd::is_readable(inode) { EPOLLIN } else { 0 }
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::TimerFd, _)) => {
            if crate::ipc::timerfd::is_readable(inode) { EPOLLIN } else { 0 }
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::SignalFd, _)) => {
            if crate::ipc::signalfd::is_readable(inode) { EPOLLIN } else { 0 }
        }
        Some((_inode, _flags, false, false, crate::vfs::FileType::InotifyFd, _)) => {
            0 // stub: never delivers events
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::PtyMaster, _)) => {
            if crate::drivers::pty::master_readable(inode as u8) { EPOLLIN | EPOLLOUT } else { EPOLLOUT }
        }
        Some((inode, _flags, false, false, crate::vfs::FileType::PtySlave, _)) => {
            if crate::drivers::pty::slave_readable(inode as u8) { EPOLLIN | EPOLLOUT } else { EPOLLOUT }
        }
        Some((inode, flags, false, false, _, mount_idx)) => {
            // Pipe — readable end signals EPOLLIN on data and EPOLLHUP on
            // writer-close EOF.  Per POSIX `poll(2)`, `POLLHUP` is set even
            // when not requested and may coexist with `POLLIN` while data
            // remains buffered.
            if flags & PIPE_FD_BIT != 0 {
                if flags & O_WRONLY_BIT == 0 {
                    if crate::ipc::pipe::pipe_has_data(inode)    { EPOLLIN }
                    else if crate::ipc::pipe::pipe_is_eof(inode) { EPOLLHUP }
                    else { 0 }
                } else {
                    EPOLLOUT
                }
            } else if mount_idx == usize::MAX && flags & SOCKET_FD_BIT != 0 {
                // Socket fd.  AF_UNIX uses an in-memory ring (always
                // writable for partial writes) — gate EPOLLIN on the
                // backend `has_data()` instead of asserting readability
                // unconditionally, which would make `epoll_wait` return
                // readable for an empty socket and force userspace to
                // burn cycles on `recvmsg → -EAGAIN` (POSIX `epoll_wait(2)`
                // edge-trigger spurious-wake guidance, and the Mozilla
                // IPC spin pattern observed under firefox-test).
                //
                // AF_INET goes through the protocol's `socket_has_data`
                // — same shape, distinct backend.
                if flags & UNIX_SOCK_BIT != 0 {
                    // EPOLLOUT only when a `write()` would make progress — the
                    // peer's recv ring has room, or the write side can no
                    // longer block (SHUT_WR / peer-gone / not-connected, where
                    // `write()` returns -EPIPE without blocking).  Advertising
                    // writable unconditionally makes a producer blocked on a
                    // full socket busy-spin epoll_wait→write→EAGAIN, the
                    // stuck-producer pattern `epoll(7)` / `poll(2)` avoid.
                    let mut ev = if crate::net::unix::writable(inode) { EPOLLOUT } else { 0 };
                    let has_d = crate::net::unix::has_data(inode);
                    // A reached SCM_RIGHTS batch confers EPOLLIN even with an
                    // empty data ring: a control-only ancillary frame
                    // (iov_len==0) IS a readable message per recvmsg(2) /
                    // unix(7) / POSIX.1-2017 SCM_RIGHTS, and epoll_wait(2)
                    // must report it so the receiver recvmsg's the fd instead
                    // of parking forever on a pure fd handoff.
                    let has_scm = crate::syscall::has_scm_deliverable(
                        inode, crate::net::unix::recv_consumed(inode));
                    // A LISTENING AF_UNIX socket with a queued connection is
                    // read-ready: accept(2) will not block.  `has_pending`
                    // reports the listen(2) accept backlog (backlog_len > 0).
                    // `poll`/`select` already gate POLLIN on it
                    // (`syscall::poll_revents` / `do_select`); without it here,
                    // an epoll-driven accept loop never wakes for an incoming
                    // connection — POLLIN under poll/select but no EPOLLIN under
                    // epoll_wait (epoll(7) / accept(2)).  A connected socketpair
                    // has backlog_len == 0, so this is a no-op for it and only
                    // restores listening-socket accept-readiness parity.
                    let has_pend = crate::net::unix::has_pending(inode);
                    if has_d || has_scm || has_pend {
                        ev |= EPOLLIN;
                    }
                    // `epoll(7)` distinguishes a read-side half-close from a
                    // full hang-up, so we report them separately:
                    //
                    //   * read-side half-close (peer `shutdown(SHUT_WR)`, or
                    //     we did `shutdown(SHUT_RD)`; the connection is still
                    //     up and still writable) → EPOLLRDHUP, plus the read
                    //     end becomes readable (read() returns 0) so EPOLLIN.
                    //     EPOLLOUT stays set — the write direction is valid.
                    //     EPOLLRDHUP means "read EOF, write still valid"; it
                    //     is NOT EPOLLHUP.
                    //
                    //   * full hang-up (SHUT_RDWR both directions, or either
                    //     endpoint fully closed) → additionally EPOLLHUP,
                    //     which `epoll(7)` defines as "connection fully dead".
                    //
                    // EPOLLHUP is always reported regardless of the interest
                    // mask; EPOLLRDHUP is only *delivered* when the caller
                    // subscribed it, via the `subscribed & ready_ev`
                    // intersection in `do_poll`.  Raising EPOLLRDHUP
                    // unconditionally here is correct — the intersection
                    // gates its delivery, per `epoll(7)`.
                    if crate::net::unix::read_shutdown(inode) {
                        ev |= EPOLLIN | EPOLLRDHUP;
                    }
                    if crate::net::unix::fully_hung_up(inode) {
                        ev |= EPOLLHUP;
                    }
                    ev
                } else {
                    let mut ev = EPOLLOUT;
                    if crate::net::socket::socket_has_data(inode) {
                        ev |= EPOLLIN;
                    }
                    // Peer read-closed / full hang-up edges, mirroring the
                    // AF_UNIX arm above.  Without these an AF_INET reader in
                    // `epoll_wait(2)` on a TCP fd is never woken on a peer
                    // FIN (CloseWait): no EPOLLIN-on-EOF, no EPOLLRDHUP, no
                    // EPOLLHUP — so it never issues the `read(2)` that
                    // returns 0 and signals end-of-response, and a close-
                    // delimited consumer (RFC 9112 §6.3) waits forever.
                    //
                    //   * read-closed (peer FIN, RFC 9293 §3.5) → the read
                    //     end is readable (read() drains the tail then
                    //     returns 0) so EPOLLIN, plus EPOLLRDHUP ("read EOF,
                    //     write still valid").  EPOLLOUT stays set.
                    //   * fully hung up (read-closed AND nothing to drain) →
                    //     EPOLLHUP, which `epoll(7)` reports regardless of
                    //     the interest mask.
                    let rc = crate::net::socket::socket_read_closed(inode);
                    let hup = crate::net::socket::socket_fully_hung_up(inode);
                    if rc {
                        ev |= EPOLLIN | EPOLLRDHUP;
                    }
                    if hup {
                        ev |= EPOLLHUP;
                    }
                    #[cfg(feature = "firefox-test")]
                    if rc || hup {
                        crate::serial_println!(
                            "[FF/tcp-eof] epoll pid={} fd={} sid={} read_closed={} hup={} events={:#x}",
                            pid, fd, inode, rc, hup, ev);
                    }
                    ev
                }
            } else {
                EPOLLIN | EPOLLOUT
            }
        }
    }
}

/// One epoll interest-set entry, with its LIVE readiness, for the kdb
/// `epoll-watch` diagnostic.  See [`epoll_watch_diag`].
pub(crate) struct EpollWatchDiag {
    /// The watched fd in the owning process's fd table.
    pub fd: usize,
    /// The caller's raw subscribed interest mask (EPOLL* bits), as stored
    /// at `epoll_ctl(ADD|MOD)` time — unmodified.
    pub subscribed: u32,
    /// The LIVE readiness mask `epoll_wait(2)` would compute right now for
    /// this fd, via the exact same `epoll_poll_events` path the wait loop
    /// uses.  EPOLLIN/EPOLLOUT/EPOLLHUP/EPOLLRDHUP/EPOLLERR.
    pub revents: u32,
    /// What `epoll_wait(2)` would actually DELIVER for this watch:
    /// `(subscribed & revents) | (revents & (EPOLLERR | EPOLLHUP))`.
    /// Non-zero here means the reactor's next `epoll_wait` returns this fd
    /// ready — so if the reactor still never drains it, the reactor THREAD
    /// is not running `epoll_wait` (parked / scheduled-out / busy).
    pub delivered: u32,
}

/// Result of an `epoll-watch` diagnostic lookup for one (pid, epfd).
pub(crate) enum EpollWatchResult {
    /// No such pid.
    NoProc,
    /// The fd is not an epoll fd in this process.
    NotEpoll,
    /// The epoll fd resolved but no `EpollInstance` matched its id.
    NoInstance,
    /// Success — the resolved instance id plus its full interest set, each
    /// entry carrying its live readiness.
    Ok { epoll_id: u64, watches: alloc::vec::Vec<EpollWatchDiag> },
}

/// Live epoll interest-set + per-fd readiness dump for the kdb `epoll-watch`
/// op.  Resolves the epoll instance for `(pid, epfd)` using the SAME by-id
/// path as `sys_epoll_wait` (FileDescriptor.inode of the `[epoll]` fd → the
/// matching `EpollInstance` in `proc.epoll_sets`), then for every watched fd
/// reports the caller's subscribed mask alongside the LIVE `epoll_poll_events`
/// result and the mask `epoll_wait(2)` would actually deliver.
///
/// This is the decisive discriminator for a wedged reactor: if the
/// content-reply channel fd is in the interest set AND `delivered` carries
/// EPOLLIN while the reactor never `recvmsg`s, the reactor thread is not
/// running `epoll_wait` (parked/starved).  If the fd is ABSENT, or `revents`
/// reports no EPOLLIN despite unread data, that is a kernel epoll
/// readiness/registration divergence per `epoll(7)`.
///
/// Read-only; takes PROCESS_TABLE only for the brief watch-list snapshot,
/// then computes readiness lock-free (each `epoll_poll_events` re-takes the
/// lock briefly per fd, exactly as the wait loop does).
pub(crate) fn epoll_watch_diag(pid: u64, epfd: usize) -> EpollWatchResult {
    use crate::ipc::epoll::{EPOLLERR, EPOLLHUP};

    // Snapshot the watch list under a brief lock hold — mirrors
    // sys_epoll_wait Step 1 (by-id lookup so a dup'd epfd resolves to the
    // same shared instance).
    let (epoll_id, watches_snap): (u64, alloc::vec::Vec<(usize, u32)>) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None    => return EpollWatchResult::NoProc,
        };
        let epoll_id = match proc.file_descriptors.get(epfd).and_then(|f| f.as_ref()) {
            Some(f) if f.open_path == "[epoll]" => f.inode,
            _                                   => return EpollWatchResult::NotEpoll,
        };
        let inst = match proc.epoll_sets.iter().find(|e| e.id == epoll_id) {
            Some(i) => i,
            None    => return EpollWatchResult::NoInstance,
        };
        (epoll_id, inst.watches.iter().map(|w| (w.fd, w.events)).collect())
    }; // lock released

    // Poll each watch lock-free — identical readiness path to sys_epoll_wait.
    let mut watches = alloc::vec::Vec::with_capacity(watches_snap.len());
    for (fd, subscribed) in watches_snap {
        let revents = epoll_poll_events(pid, fd);
        let delivered = (subscribed & revents) | (revents & (EPOLLERR | EPOLLHUP));
        watches.push(EpollWatchDiag { fd, subscribed, revents, delivered });
    }
    EpollWatchResult::Ok { epoll_id, watches }
}

/// Readiness predicate for an AF_UNIX recv: the socket can return *something*
/// other than EAGAIN right now.  True when the recv ring has bytes (STREAM) or
/// a queued message (SEQPACKET) — `net::unix::has_data`; when a control-only
/// `SCM_RIGHTS` ancillary frame is deliverable at the reader's current stream
/// position (`has_scm_deliverable`, an empty-data readable message per
/// recvmsg(2) / unix(7)); or when the read direction is shut (orderly EOF,
/// which read_msg surfaces as `Ok((0,0))`).  Mirrors the POLLIN edge the poll
/// path already exposes, so a blocking recvmsg/recvfrom parks until exactly the
/// condition that will let it make progress.
fn unix_recv_ready(unix_id: u64) -> bool {
    if crate::net::unix::has_data(unix_id) {
        return true;
    }
    if crate::net::unix::read_shutdown(unix_id) {
        return true;
    }
    let consumed = crate::net::unix::recv_consumed(unix_id);
    crate::syscall::has_scm_deliverable(unix_id, consumed)
}

/// Block the calling thread until an AF_UNIX recv on `unix_id` can make
/// progress, or a bounded wait deadline / pending signal fires.
///
/// Per POSIX recvmsg(2) / recvfrom(2) and unix(7): a receive on a socket that
/// is NOT in non-blocking mode (no `O_NONBLOCK` on the description, no
/// `MSG_DONTWAIT` in `flags`) MUST block until a message is available — it must
/// NOT return -EAGAIN on a momentarily-empty queue.  The prior AF_UNIX recv
/// paths called `read`/`read_msg` exactly once and returned -EAGAIN on an empty
/// ring regardless of blocking mode, which broke any blocking-recvmsg consumer
/// (e.g. a SOCK_SEQPACKET request/response broker that loops on recvmsg with no
/// MSG_DONTWAIT and only retries on EINTR — a spurious EAGAIN there tears the
/// channel down).  This loop mirrors the AF_INET recvfrom(2) blocking wait.
///
/// Returns `Ok(())` when the socket is ready to be drained (the caller then
/// performs the actual `read`/`read_msg`, which may still return 0 for an
/// orderly EOF), or `Err(errno)` to be returned to userspace directly:
///   * `-4`  (EINTR)  — a deliverable signal arrived during the wait.
///   * `-11` (EAGAIN) — the bounded wait deadline elapsed with no data.  This
///     preserves liveness: a never-arriving message cannot pin a syscall
///     forever.  Most IPC brokers retry, and the deadline (≈30 s) is far longer
///     than any in-flight request round-trip.
///
/// When `blocking` is false (non-blocking fd or MSG_DONTWAIT) this returns
/// `Ok(())` immediately so the single drain attempt below yields the correct
/// EAGAIN-on-empty behaviour unchanged.
fn unix_recv_block_wait(unix_id: u64, pid: u64, blocking: bool) -> Result<(), i64> {
    if !blocking {
        return Ok(());
    }
    // Fast path: already ready — no need to read get_ticks / yield at all.
    if unix_recv_ready(unix_id) {
        return Ok(());
    }
    let deadline = crate::arch::x86_64::irq::get_ticks() + 3000; // ≈30 s upper bound
    while !unix_recv_ready(unix_id) {
        if signal_pending(pid) {
            return Err(-4); // EINTR
        }
        // Pump the network stack so any cross-process AF_UNIX write that
        // landed since the last check becomes visible, and so SLIRP/virtio
        // RX is serviced (a content-process reply travels through net::poll's
        // wake bell on the unix backend).
        crate::net::poll();
        if crate::arch::x86_64::irq::get_ticks() >= deadline {
            return Err(-11); // EAGAIN — bounded-wait liveness floor
        }
        crate::sched::yield_cpu();
    }
    Ok(())
}

/// Read the `O_NONBLOCK` (0x800) flag off process `pid`'s fd-table slot `fd`.
/// Returns false if the fd is absent (the caller has already validated the fd
/// as a socket before reaching the recv drain, so a missing slot here only
/// occurs on a teardown race — defaulting to "blocking" is the safe choice and
/// the subsequent drain will surface EBADF/EAGAIN as appropriate).
fn fd_is_nonblocking(pid: u64, fd: usize) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.file_descriptors.get(fd).and_then(|f| f.as_ref()))
        .map(|f| (f.flags & 0x0800) != 0)
        .unwrap_or(false)
}

/// Returns true if a deliverable (pending && !blocked) signal is queued for `pid`.
/// Used by blocking syscalls (epoll_wait, select) to honour the POSIX contract
/// that they must abort with EINTR when a signal is delivered during the wait.
fn signal_pending(pid: u64) -> bool {
    let procs = crate::proc::PROCESS_TABLE.lock();
    procs.iter().find(|p| p.pid == pid)
        .and_then(|p| p.signal_state.as_ref())
        .map(|s| s.has_pending())
        .unwrap_or(false)
}

/// epoll_create / epoll_create1 — allocate a new epoll fd.
fn sys_epoll_create1(_flags: u32) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None    => return -9, // EBADF
    };
    // Find the lowest free fd slot.
    let slot = proc.file_descriptors.iter().position(|f| f.is_none())
        .unwrap_or_else(|| {
            proc.file_descriptors.push(None);
            proc.file_descriptors.len() - 1
        });
    // Extend fd table if needed.
    while proc.file_descriptors.len() <= slot {
        proc.file_descriptors.push(None);
    }
    // Allocate a fresh epoll id and stamp it into BOTH the FileDescriptor
    // (so dup(2) / fcntl(F_DUPFD) carries it forward in the cloned fd) and
    // the EpollInstance (so the by-id lookup in sys_epoll_ctl/wait finds
    // the same instance through any dup of the original epfd).  Without
    // this, dup'ing an epoll fd creates a second FileDescriptor whose
    // `open_path == "[epoll]"` check passes but whose post-check
    // `epoll_sets.iter().find(|e| e.epfd == NEW_FD)` returns None — and
    // the caller sees a spurious -EBADF on the dup'd epfd.  tokio's signal
    // driver hits exactly this pattern: it F_DUPFDs the runtime epoll
    // (mio internal fd=4) into a signal-driver-local epfd (typically 6),
    // then epoll_ctl's a signal pipe through the dup.  Verified failing
    // pre-fix; verified working post-fix.  See PIVOT-I2 Phase D, 2026-05-23.
    let (epoll_instance, epoll_id) = crate::ipc::epoll::EpollInstance::new_with_id(slot);
    proc.file_descriptors[slot] = Some(crate::vfs::FileDescriptor {
        inode:     epoll_id,
        mount_idx: 0,
        offset:    0,
        flags:     0,
        file_type: crate::vfs::FileType::CharDevice,
        is_console: false,
        cloexec:   false,
        open_path: alloc::string::String::from("[epoll]"),
    });
    proc.epoll_sets.push(epoll_instance);
    slot as i64
}

/// epoll_ctl — add/modify/delete a watched fd.
fn sys_epoll_ctl(epfd: usize, op: u64, fd: usize, event_ptr: u64) -> i64 {
    use crate::ipc::epoll::{EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, EpollEvent};
    let pid = crate::proc::current_pid_lockless();

    // Read the caller's epoll_event (only needed for ADD / MOD).
    let (events, data) = if event_ptr != 0 && op != EPOLL_CTL_DEL {
        let ev = unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::read_unaligned(event_ptr as *const EpollEvent)
        };
        (ev.events, ev.data)
    } else {
        (0u32, 0u64)
    };

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None    => return -9, // EBADF
    };

    // Verify epfd refers to an epoll object AND capture the epoll id
    // (stored in FileDescriptor.inode at create-time).  We use the id —
    // not the epfd value — to look up the shared EpollInstance, so dup'd
    // epoll fds (signal-hook-registry / tokio signal driver pattern) all
    // resolve to the same instance.  See `EpollInstance::new_with_id`
    // and `sys_epoll_create1` for the by-id design rationale.
    //
    // Per POSIX dup(2) and Linux epoll(7): registrations made through one
    // fd of a dup'd pair are visible through the other.  Without by-id
    // lookup we incorrectly return -EBADF on dup'd epfds, breaking any
    // runtime that opaquely dup's its epoll handle (tokio + signal-hook).
    let epoll_id = match proc.file_descriptors.get(epfd).and_then(|f| f.as_ref()) {
        Some(f) if f.open_path == "[epoll]" => f.inode,
        _                                   => return -9, // EBADF
    };

    let inst = match proc.epoll_sets.iter_mut().find(|e| e.id == epoll_id) {
        Some(i) => i,
        None    => return -9, // EBADF
    };

    match op {
        EPOLL_CTL_ADD => {
            if inst.add(fd, events, data) { 0 } else { -17 } // EEXIST
        }
        EPOLL_CTL_DEL => {
            if inst.del(fd) { 0 } else { -2 } // ENOENT
        }
        EPOLL_CTL_MOD => {
            if inst.modify(fd, events, data) { 0 } else { -2 } // ENOENT
        }
        _ => -22, // EINVAL
    }
}

/// epoll_wait — collect ready events into caller's buffer.
fn sys_epoll_wait(epfd: usize, events_ptr: u64, maxevents: usize, timeout_ms: i32) -> i64 {
    use crate::ipc::epoll::{EpollEvent, EPOLLERR, EPOLLHUP, EPOLLET, EPOLLIN};
    if maxevents == 0 { return -22; } // EINVAL
    let pid = crate::proc::current_pid_lockless();

    // ── Step 1: snapshot the watch list while briefly holding the lock ────────
    // Look up the EpollInstance by its per-process id (stamped into
    // FileDescriptor.inode at epoll_create1 time) NOT by the epfd —
    // dup'd epoll fds share the inode and thus the same instance.
    // Symmetric with sys_epoll_ctl above; see that block for the full
    // by-id rationale (PIVOT-I2 Phase D, 2026-05-23).
    // Each snapshot entry is `(fd, subscribed, data, et_seen)`.  `et_seen`
    // is the per-watch edge-trigger baseline for `EPOLLET` watches (the
    // subset of readiness bits already delivered on a prior call and still
    // continuously asserted); 0 for level-triggered watches.  `epoll_id`
    // is retained so the (possibly updated) edge baselines can be written
    // back into the live `EpollInstance` after the poll completes.
    let epoll_id: u64;
    let watches_snap: alloc::vec::Vec<(usize, u32, u64, u32)>;
    // Per-watch eventfd slot id (index-aligned with `watches_snap`);
    // `u64::MAX` for non-eventfd watches.  Resolved once under the same
    // lock hold so the EPOLLET write-edge re-fire below (see `efd_edge`)
    // does not need a PROCESS_TABLE lookup per poll iteration.
    let efd_for: alloc::vec::Vec<u64>;
    {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None    => return -9, // EBADF
        };
        epoll_id = match proc.file_descriptors.get(epfd).and_then(|f| f.as_ref()) {
            Some(f) if f.open_path == "[epoll]" => f.inode,
            _                                   => return -9, // EBADF
        };
        let inst = match proc.epoll_sets.iter().find(|e| e.id == epoll_id) {
            Some(i) => i,
            None    => return -9,
        };
        watches_snap = inst.watches.iter()
            .map(|w| (w.fd, w.events, w.data, w.et_seen)).collect();
        efd_for = inst.watches.iter().map(|w| {
            proc.file_descriptors.get(w.fd)
                .and_then(|f| f.as_ref())
                .filter(|f| f.file_type == crate::vfs::FileType::EventFd)
                .map(|f| f.inode)
                .unwrap_or(u64::MAX)
        }).collect();
    } // lock released here

    // Live edge-trigger baselines, one per snapshot entry (index-aligned).
    // Seeded from the stored `et_seen` and mutated by `do_poll` / `probe_ready`
    // as edges are consumed and re-armed; flushed back to the live instance
    // at Step 3.  A `RefCell` lets the `Fn` closures below mutate it without
    // capturing `&mut` (they are also called from the park predicate path).
    let et_state: core::cell::RefCell<alloc::vec::Vec<u32>> =
        core::cell::RefCell::new(watches_snap.iter().map(|w| w.3).collect());

    // Compute the mask `epoll_wait(2)` would deliver for one watch, honouring
    // the level-vs-edge contract of `epoll(7)`.
    //
    //   * The base "interest" is built as two disjoint parts, unchanged from
    //     the level-triggered ABI fix:
    //       - the caller-subscribed bits currently ready (`subscribed & ready`)
    //       - any EPOLLERR / EPOLLHUP ready even when unsubscribed
    //         (`ready & (EPOLLERR | EPOLLHUP)`).
    //     EPOLLRDHUP is NOT always-on, so it flows through the first term only.
    //     The stored `subscribed` mask is the caller's raw interest and is
    //     never mutated.
    //
    //   * Level-triggered watch (no EPOLLET): the full `interest` is delivered
    //     on every call as long as the condition holds — identical to before.
    //
    //   * Edge-triggered watch (EPOLLET): per `epoll(7)` ("Level-triggered and
    //     edge-triggered"), a readiness bit is delivered only on its rising
    //     edge — when the fd transitions from not-having to having it — and not
    //     again until that condition is first cleared and then re-occurs.  The
    //     per-watch `seen` baseline (in `et_state[idx]`) records which bits
    //     were already delivered and have stayed continuously asserted.  We
    //     deliver only the newly-risen bits (`interest & !seen`), re-arm any
    //     bit that has since dropped (`seen &= interest`), and fold the just-
    //     reported bits into the baseline (`seen |= report`).  A watched fd
    //     that stays level-ready without the consumer draining it (e.g. a
    //     wakeup eventfd whose counter the reactor leaves nonzero) is reported
    //     exactly once, so `epoll_wait` blocks on the next call instead of
    //     spinning — matching Linux edge-trigger semantics.
    //
    // Read-only edge/level computation: the mask `epoll_wait(2)` WOULD deliver
    // for watch `idx` right now, without mutating the baseline.  The effective
    // post-re-arm baseline is `seen & interest`, so the deliverable set is
    // `interest & !(seen & interest)` = `interest & !seen`; the re-arm step is
    // pure bookkeeping for persistence and does not change the current report.
    // Used by `probe_ready` so the park predicate never *consumes* an edge.
    let peek_for = |idx: usize, subscribed: u32, ready_ev: u32| -> u32 {
        let interest =
            (subscribed & ready_ev) | (ready_ev & (EPOLLERR | EPOLLHUP));
        if subscribed & EPOLLET == 0 {
            return interest; // level-triggered: report whenever ready
        }
        let seen = et_state.borrow()[idx];
        interest & !seen // rising-edge bits only (read-only)
    };

    // Consuming edge/level computation: same deliverable mask as `peek_for`,
    // but it also commits the baseline update for EPOLLET watches (re-arm
    // dropped bits, then mark the just-delivered bits seen).  Only the call
    // sites that ACTUALLY return events to userspace use this — never the park
    // predicate — so a rising edge is consumed exactly once.
    let deliver_for = |idx: usize, subscribed: u32, ready_ev: u32| -> u32 {
        let interest =
            (subscribed & ready_ev) | (ready_ev & (EPOLLERR | EPOLLHUP));
        if subscribed & EPOLLET == 0 {
            return interest; // level-triggered: report whenever ready
        }
        let mut et = et_state.borrow_mut();
        let seen = &mut et[idx];
        *seen &= interest;            // re-arm any bit that dropped to not-ready
        let report = interest & !*seen; // rising-edge bits only
        *seen |= report;              // remember what we just delivered
        report
    };

    // Wakeup-driven EPOLLET re-fire for eventfds.  The `et_seen` baseline
    // above models edge-triggering as a LEVEL DELTA ("became ready after
    // not being ready"), but per eventfd(2) every successful write(2) is a
    // fresh readiness notification, and per epoll(7) an edge-triggered
    // watcher gets one event per notification — even when the counter was
    // already nonzero.  A reactor that deliberately never drains its wakeup
    // eventfd (the common waker pattern) would otherwise see exactly one
    // event ever: write #2 against the still-nonzero counter computes
    // `interest & !seen == 0` and the parked epoll_wait never returns.
    //
    // This helper reports EPOLLIN for an EPOLLET eventfd watch whose slot
    // carries a pending write edge.  `consume == true` (delivery path)
    // claims the edge via `take_write_edge`; the park predicate passes
    // `consume == false` and only peeks.  When the level-delta machinery in
    // `deliver_for` already reports EPOLLIN (`already & EPOLLIN != 0`), the
    // pending edge is folded into that delivery — claimed but not
    // re-reported — so one write never yields two events.  Scoped strictly
    // to eventfd watches; all other fd types keep the level-delta model.
    let efd_edge = |idx: usize, subscribed: u32, ready_ev: u32,
                    already: u32, consume: bool| -> u32 {
        if efd_for[idx] == u64::MAX        { return 0; } // not an eventfd
        if subscribed & EPOLLET == 0       { return 0; } // level-triggered
        if subscribed & EPOLLIN == 0       { return 0; } // not read-interested
        if ready_ev   & EPOLLIN == 0       { return 0; } // counter is zero
        let pending = if consume {
            crate::ipc::eventfd::take_write_edge(efd_for[idx])
        } else {
            crate::ipc::eventfd::peek_write_edge(efd_for[idx])
        };
        if pending && already & EPOLLIN == 0 { EPOLLIN } else { 0 }
    };

    // ── Step 2: poll without holding the lock ────────────────────────────────
    let do_poll = |fired: &mut alloc::vec::Vec<EpollEvent>| {
        for (idx, &(fd, subscribed, data, _)) in watches_snap.iter().enumerate() {
            if fired.len() >= maxevents { break; }
            let ready_ev = epoll_poll_events(pid, fd);
            let mut report = deliver_for(idx, subscribed, ready_ev);
            report |= efd_edge(idx, subscribed, ready_ev, report, true);
            if report != 0 {
                // Per-fd delivery trace (firehose family — trace builds only).
                // Records the EXACT event mask handed to userspace so a
                // spurious EPOLLHUP/EPOLLRDHUP on an IPC channel fd is
                // directly observable, not inferred from later behaviour.
                #[cfg(feature = "firefox-test-trace")]
                crate::serial_fast_println!(
                    "[EPOLL_EV] pid={} fd={} report={:#x} ready={:#x} sub={:#x}",
                    pid, fd, report, ready_ev, subscribed);
                fired.push(EpollEvent { events: report, data });
            }
        }
    };

    // Read-only readiness probe over the watch snapshot — true if any watched
    // fd currently has a deliverable event.  Mirrors `do_poll`'s edge/level
    // masking but NON-consumingly (via `peek_for`): an EPOLLET fd whose edge
    // has already been delivered and merely stays level-ready must NOT keep
    // the predicate "ready" — otherwise the park never commits and the spin
    // persists.  Allocates nothing and pushes nothing; used as the
    // recheck-under-lock predicate for `wait_poll_event` so the
    // check-and-park lost-wakeup window is closed (prepare-to-wait).
    let probe_ready = || -> bool {
        for (idx, &(fd, subscribed, _data, _)) in watches_snap.iter().enumerate() {
            let ready_ev = epoll_poll_events(pid, fd);
            let peeked = peek_for(idx, subscribed, ready_ev);
            if peeked != 0 { return true; }
            // A pending eventfd write edge is deliverable even when the
            // level-delta peek reports nothing (counter stayed nonzero
            // across the write) — without this the parked waiter wakes on
            // the poll bell, computes 0, and re-parks forever.
            if efd_edge(idx, subscribed, ready_ev, peeked, false) != 0 {
                return true;
            }
        }
        false
    };

    let mut fired: alloc::vec::Vec<EpollEvent> = alloc::vec::Vec::new();
    do_poll(&mut fired);

    // Per `man 2 epoll_wait`: the call must block until at least one fd is
    // ready, the timeout expires, or a signal is delivered. Returning 0 early
    // is a contract violation — applications that use the canonical self-pipe
    // wakeup pattern (write to a pipe-write end to wake a sibling thread
    // blocked in epoll_wait) will busy-loop instead of waking on demand.
    //
    // We poll on a 10ms cadence (1 tick) and re-check until one of the three
    // termination conditions fires. Wake-on-readiness (notifying epoll
    // instances directly when a watched fd transitions to ready) is a
    // correctness-preserving optimisation tracked as follow-up work.
    if fired.is_empty() && timeout_ms != 0 {
        // Pre-wait network pump: drain any RX frames that arrived between the
        // initial do_poll above and now, and run tcp_timer_tick() to drain any
        // queued send_buffer entries.  Mirrors the identical pre-wait pump in
        // poll(2) (syscall nr 7).  Without this first pump, a fresh
        // epoll_wait call immediately after connect(2) may miss a SYN-ACK or
        // ACK that was already DMA'd into the NIC RX ring.
        crate::net::poll();
        do_poll(&mut fired);
        let deadline_tick = if timeout_ms < 0 {
            u64::MAX // infinite — block until ready or signal
        } else {
            let now = crate::arch::x86_64::irq::get_ticks();
            now.saturating_add(((timeout_ms as u64) / 10).max(1))
        };
        if fired.is_empty() {
            // Per-object interest set: the concrete readiness objects the
            // watched fds resolve to, so the per-object poll-bell drain wakes
            // this epoll_wait parker only on edges of the EXACT fds it watches
            // (intra-class herd collapse — the dominant cost on the heavy
            // multi-thread FF render).  Computed once outside the loop — the
            // watch set is fixed for the lifetime of this epoll_wait call.
            // Conservative superset: any unclassifiable fd ⇒ wake-on-class.
            let (bell_mask, bell_objects) = bell_watch_for_fds(
                pid, watches_snap.iter().map(|&(fd, ..)| fd));
            loop {
                // Park on the global poll bell.  Pipe/eventfd writes ring it
                // (see `crate::ipc::waitlist::ring_poll_bell`); the scheduler
                // tick wakes us at the deadline.  Replaces the prior
                // 10 ms-tick sleep loop and is the change responsible for
                // closing the post-PR-#119 epoll-spin plateau.
                //
                // `probe_ready` is re-run under the POLL_BELL lock before
                // the park commits (prepare-to-wait), so a writer that makes
                // a watched fd ready in the window between our last `do_poll`
                // and the park cannot lose the readiness edge: it is
                // serialized on POLL_BELL and either makes the recheck
                // observe ready (we skip parking) or finds us enqueued (it
                // drains us).  The wake-side net/x11 pumps run only when we
                // actually parked.
                let ready_in_window =
                    crate::ipc::waitlist::wait_poll_event_obj(
                        deadline_tick, bell_mask, &bell_objects, &probe_ready);
                if ready_in_window {
                    do_poll(&mut fired);
                    if !fired.is_empty() { break; }
                }
                // Pump the NIC RX ring and TCP timers on every wakeup.
                // This is the symmetric partner to the identical call in
                // poll(2) (~line 1447).  Without it, a tokio/reqwest runtime
                // that blocks in epoll_wait never processes incoming TCP ACKs:
                //
                //   1. The NIC DMA ring fills with ACK frames from the peer.
                //   2. tcp_timer_tick() never fires → send_buffer never drains.
                //   3. send_data_inner() accumulates data in send_buffer once
                //      the initial congestion window (1 MSS = 1 460 B) is
                //      exhausted.
                //   4. write(2) returns Ok(n) while data silently queues,
                //      never reaching the wire — producing the W=465 / R=0
                //      asymmetry observed in the Oracle daemon-mode 180 s soak
                //      (PIVOT-I2 Phase D, 2026-05-23, NDE-5).
                //
                // Per RFC 9293 §3.8.1, the sender MUST keep the pipe full
                // while SND.WND and cwnd permit; that is only possible when
                // ACKs are delivered and SND.UNA advances.
                crate::net::poll();
                do_poll(&mut fired);
                if !fired.is_empty() { break; }
                // Signal pending → return -EINTR per spec.
                if signal_pending(pid) { return -4; } // EINTR
                let now = crate::arch::x86_64::irq::get_ticks();
                if now >= deadline_tick { break; }
            }
        }
    }

    // ── Step 3: flush updated EPOLLET edge baselines back to the instance ────
    // `et_state` accumulated the per-watch rising-edge consumption during the
    // poll/wait loop above.  Persist it so a subsequent `epoll_wait` on the
    // same instance honours the edge (does not re-report a still-asserted
    // EPOLLET condition).  Matched by fd — not snapshot index — so a watch
    // that an `epoll_ctl(DEL/ADD)` reordered between snapshot and now is left
    // untouched (a concurrently re-added fd starts with a fresh `et_seen=0`).
    // Only entries whose subscribed mask carried EPOLLET need writing; LT
    // watches keep `et_seen == 0` throughout, so they are skipped.
    {
        let et = et_state.borrow();
        let needs_flush = watches_snap.iter().enumerate().any(|(i, w)| {
            (w.1 & EPOLLET != 0) && (et[i] != w.3)
        });
        if needs_flush {
            let mut procs = crate::proc::PROCESS_TABLE.lock();
            if let Some(proc) = procs.iter_mut().find(|p| p.pid == pid) {
                if let Some(inst) = proc.epoll_sets.iter_mut().find(|e| e.id == epoll_id) {
                    for (i, snap) in watches_snap.iter().enumerate() {
                        if snap.1 & EPOLLET == 0 { continue; }
                        if let Some(w) = inst.watches.iter_mut()
                            .find(|w| w.fd == snap.0 && w.events == snap.1)
                        {
                            w.et_seen = et[i];
                        }
                    }
                }
            }
        }
    }

    // ── Step 4: copy events to the caller's buffer ───────────────────────────
    let count = fired.len();
    if count > 0 && events_ptr != 0 {
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            core::ptr::copy_nonoverlapping(
                fired.as_ptr(),
                events_ptr as *mut EpollEvent,
                count,
            );
        }
    }
    count as i64
}

// ============================================================================
// timerfd syscalls
// ============================================================================

/// `timerfd_create(clockid, flags)` — allocate a timer notification fd.
fn sys_timerfd_create(clockid: u32) -> i64 {
    let slot_id = crate::ipc::timerfd::create(clockid);
    if slot_id == u64::MAX { return -24; } // EMFILE

    let pid = crate::proc::current_pid_lockless();
    let fd = crate::vfs::FileDescriptor::timer_fd(slot_id);

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => { crate::ipc::timerfd::close(slot_id); return -3; }
    };
    for (i, slot) in proc.file_descriptors.iter().enumerate() {
        if slot.is_none() {
            proc.file_descriptors[i] = Some(fd);
            return i as i64;
        }
    }
    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        return idx as i64;
    }
    crate::ipc::timerfd::close(slot_id);
    -24 // EMFILE
}

/// `timerfd_settime(fd, flags, *new_value, *old_value)` — arm/disarm a timer.
///
/// `new_value` is a `struct itimerspec { it_interval, it_value }` where each
/// timespec is `{ tv_sec: i64, tv_nsec: i64 }` (16 bytes each, 32 bytes total).
fn sys_timerfd_settime(fd_num: u64, flags: u32, new_value_ptr: u64, old_value_ptr: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    if !crate::syscall::is_timerfd_fd(pid, fd_num as usize) { return -9; } // EBADF
    let slot_id = crate::syscall::get_timerfd_id(pid, fd_num as usize);

    // Read new_value itimerspec (32 bytes): interval (16) then value (16).
    if !crate::syscall::validate_user_ptr(new_value_ptr, 32) { return -14; } // EFAULT
    let (int_sec, int_nsec, val_sec, val_nsec) = unsafe {
        let p = new_value_ptr as *const i64;
        let int_sec  = *p.add(0) as u64;
        let int_nsec = *p.add(1) as u64;
        let val_sec  = *p.add(2) as u64;
        let val_nsec = *p.add(3) as u64;
        (int_sec, int_nsec, val_sec, val_nsec)
    };
    let interval_ns = int_sec.saturating_mul(1_000_000_000).saturating_add(int_nsec);
    let value_ns    = val_sec.saturating_mul(1_000_000_000).saturating_add(val_nsec);

    match crate::ipc::timerfd::settime(slot_id, flags, value_ns, interval_ns) {
        None => -9, // EBADF
        Some((old_int_ns, old_val_ns)) => {
            // Optionally write old_value back.
            if old_value_ptr != 0 && crate::syscall::validate_user_ptr(old_value_ptr, 32) {
                let old_int_sec  = (old_int_ns / 1_000_000_000) as i64;
                let old_int_nsec = (old_int_ns % 1_000_000_000) as i64;
                let old_val_sec  = (old_val_ns / 1_000_000_000) as i64;
                let old_val_nsec = (old_val_ns % 1_000_000_000) as i64;
                unsafe {
                    let p = old_value_ptr as *mut i64;
                    *p.add(0) = old_int_sec;
                    *p.add(1) = old_int_nsec;
                    *p.add(2) = old_val_sec;
                    *p.add(3) = old_val_nsec;
                }
            }
            0
        }
    }
}

/// `timerfd_gettime(fd, *curr_value)` — read current timer setting.
fn sys_timerfd_gettime(fd_num: u64, curr_value_ptr: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    if !crate::syscall::is_timerfd_fd(pid, fd_num as usize) { return -9; } // EBADF
    let slot_id = crate::syscall::get_timerfd_id(pid, fd_num as usize);
    let (interval_ns, value_ns) = crate::ipc::timerfd::gettime(slot_id);

    if curr_value_ptr != 0 && crate::syscall::validate_user_ptr(curr_value_ptr, 32) {
        let int_sec  = (interval_ns / 1_000_000_000) as i64;
        let int_nsec = (interval_ns % 1_000_000_000) as i64;
        let val_sec  = (value_ns   / 1_000_000_000) as i64;
        let val_nsec = (value_ns   % 1_000_000_000) as i64;
        unsafe {
            let p = curr_value_ptr as *mut i64;
            *p.add(0) = int_sec;
            *p.add(1) = int_nsec;
            *p.add(2) = val_sec;
            *p.add(3) = val_nsec;
        }
    }
    0
}

// ============================================================================
// signalfd4 syscall
// ============================================================================

/// `signalfd4(fd, *sigmask, sizemask, flags)` — create or update a signalfd.
///
/// If `fd == -1`, create a new signalfd. Otherwise update the mask of fd.
fn sys_signalfd4(fd_num: u64, mask_ptr: u64, sizemask: u64, _flags: u32) -> i64 {
    if sizemask < 8 || !crate::syscall::validate_user_ptr(mask_ptr, 8) { return -22; } // EINVAL/EFAULT
    let sigmask = unsafe { *(mask_ptr as *const u64) };
    let pid = crate::proc::current_pid_lockless();

    // fd == u64::MAX means -1 (create new).
    if fd_num == u64::MAX || fd_num as i64 == -1 {
        let slot_id = crate::ipc::signalfd::create(pid, sigmask);
        if slot_id == u64::MAX { return -24; } // EMFILE

        let fd = crate::vfs::FileDescriptor::signal_fd(slot_id);
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        let proc = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => { crate::ipc::signalfd::close(slot_id); return -3; }
        };
        for (i, slot) in proc.file_descriptors.iter().enumerate() {
            if slot.is_none() {
                proc.file_descriptors[i] = Some(fd);
                return i as i64;
            }
        }
        if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
            let idx = proc.file_descriptors.len();
            proc.file_descriptors.push(Some(fd));
            return idx as i64;
        }
        crate::ipc::signalfd::close(slot_id);
        -24 // EMFILE
    } else {
        // Update existing signalfd's mask.
        if !crate::syscall::is_signalfd_fd(pid, fd_num as usize) { return -9; } // EBADF
        crate::ipc::signalfd::update_mask(crate::syscall::get_signalfd_id(pid, fd_num as usize), sigmask);
        fd_num as i64
    }
}

// ============================================================================
// inotify syscalls
// ============================================================================

/// `inotify_init1(flags)` — create an inotify file descriptor.
fn sys_inotify_init1(_flags: u32) -> i64 {
    let slot_id = crate::ipc::inotify::create();
    if slot_id == u64::MAX { return -24; } // EMFILE

    let pid = crate::proc::current_pid_lockless();
    let fd = crate::vfs::FileDescriptor::inotify_fd(slot_id);

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => { crate::ipc::inotify::close(slot_id); return -3; }
    };
    for (i, slot) in proc.file_descriptors.iter().enumerate() {
        if slot.is_none() {
            proc.file_descriptors[i] = Some(fd);
            return i as i64;
        }
    }
    if proc.file_descriptors.len() < crate::vfs::MAX_FDS_PER_PROCESS {
        let idx = proc.file_descriptors.len();
        proc.file_descriptors.push(Some(fd));
        return idx as i64;
    }
    crate::ipc::inotify::close(slot_id);
    -24
}

/// `inotify_add_watch(fd, pathname, mask)` — add a watch descriptor.
fn sys_inotify_add_watch(fd_num: u64, path_ptr: u64, mask: u32) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    if !crate::syscall::is_inotify_fd(pid, fd_num as usize) { return -9; } // EBADF
    let id = crate::syscall::get_inotify_id(pid, fd_num as usize);
    let path_bytes = read_cstring_from_user(path_ptr);
    let path = core::str::from_utf8(&path_bytes).unwrap_or("");
    let wd = crate::ipc::inotify::add_watch(id, path, mask);
    if wd < 0 { -1 } else { wd as i64 }
}

/// `inotify_rm_watch(fd, wd)` — remove a watch descriptor.
fn sys_inotify_rm_watch(fd_num: u64, wd: i32) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    if !crate::syscall::is_inotify_fd(pid, fd_num as usize) { return -9; } // EBADF
    let id = crate::syscall::get_inotify_id(pid, fd_num as usize);
    if crate::ipc::inotify::rm_watch(id, wd) { 0 } else { -22 }
}

// ============================================================================
// T0/T1 syscalls — creat, getdents, alarm, setitimer, getitimer,
//                  mkdirat, unlinkat, renameat, preadv, pwritev
// ============================================================================

// PIT ticks per second (100 Hz).
const TICKS_PER_SEC: u64 = 100;

/// Deliver SIGALRM if the alarm deadline has passed.  Called at the top of
/// every Linux syscall dispatch so delivery is prompt without requiring the
/// timer ISR to hold PROCESS_TABLE.
///
/// If the alarm was set with a non-zero interval (setitimer repeating), the
/// timer is automatically re-armed.
///
/// Exposed as `pub` so the test runner can exercise alarm delivery directly
/// without going through a full syscall dispatch.
pub fn check_and_deliver_alarm_pub(pid: u64) { check_and_deliver_alarm(pid); }

fn check_and_deliver_alarm(pid: u64) {
    let now = crate::arch::x86_64::irq::get_ticks();
    // Fast path: check deadline without holding the process lock.
    // We read alarm_deadline_ticks without a lock; the field is only written
    // by this same process (in syscall context, single-threaded per-process
    // alarm state), so this is safe for the non-zero quick-exit check.
    let deadline = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p.alarm_deadline_ticks,
            None => return,
        }
    };
    if deadline == 0 || now < deadline {
        return;
    }
    // Alarm has expired — queue SIGALRM and re-arm if interval is set.
    let mut queued = false;
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let interval = p.alarm_interval_ticks;
            if interval > 0 {
                // Periodic timer: advance deadline by one (or more) intervals so
                // we never fall behind more than one period.
                let periods = ((now - p.alarm_deadline_ticks) / interval) + 1;
                p.alarm_deadline_ticks += periods * interval;
            } else {
                p.alarm_deadline_ticks = 0; // one-shot: disarm
            }
            if let Some(ref mut ss) = p.signal_state {
                ss.send(crate::signal::SIGALRM);
                // Keep the fast-path hint coherent after the direct
                // `send` (the `ss.send` overload doesn't update it).
                crate::proc::signal_pending_hint_set(pid, ss.pending);
                queued = true;
            }
        }
    } // drop procs lock before bell-ring
    if queued {
        crate::ipc::waitlist::ring_poll_bell_for(
            crate::ipc::waitlist::PollBellSource::SignalInject);
        // Mirror the dual-attribution from signal::kill — signalfd
        // readability is a direct function of `pending`.
        crate::ipc::waitlist::BELL_RINGS_BY_SOURCE
            [crate::ipc::waitlist::PollBellSource::Signalfd as usize]
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// alarm(seconds) — POSIX.1 one-shot SIGALRM timer.
///
/// Schedules delivery of SIGALRM after `seconds` wall-clock seconds.
/// Setting seconds=0 cancels any pending alarm.
/// Returns the number of seconds remaining in any previously scheduled alarm,
/// or 0 if no alarm was set.
fn sys_alarm(seconds: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let now = crate::arch::x86_64::irq::get_ticks();
    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return 0,
    };
    // Calculate remaining time on the old alarm (return value).
    let old_remaining = if proc.alarm_deadline_ticks > now {
        // Round up to whole seconds.
        (proc.alarm_deadline_ticks - now + TICKS_PER_SEC - 1) / TICKS_PER_SEC
    } else {
        0
    };
    // Arm (or disarm) the new alarm.
    if seconds == 0 {
        proc.alarm_deadline_ticks = 0;
    } else {
        proc.alarm_deadline_ticks = now + seconds * TICKS_PER_SEC;
    }
    proc.alarm_interval_ticks = 0; // alarm is always one-shot
    old_remaining as i64
}

/// setitimer(which, new_value, old_value) — POSIX interval timer.
///
/// Only ITIMER_REAL (which=0) is implemented; ITIMER_VIRTUAL (1) and
/// ITIMER_PROF (2) return -EINVAL.
///
/// struct itimerval layout (x86-64):
///   it_interval: { tv_sec: i64 @0, tv_usec: i64 @8 }  (period)
///   it_value:    { tv_sec: i64 @16, tv_usec: i64 @24 } (time until first expiry)
fn sys_setitimer(which: u64, new_val_ptr: u64, old_val_ptr: u64) -> i64 {
    const ITIMER_REAL: u64 = 0;
    if which != ITIMER_REAL {
        // ITIMER_VIRTUAL / ITIMER_PROF — not implemented.
        crate::serial_println!("[alarm] setitimer: which={} not implemented (EINVAL)", which);
        return -22; // EINVAL
    }

    let pid = crate::proc::current_pid_lockless();
    let now = crate::arch::x86_64::irq::get_ticks();

    // Read the new itimerval before acquiring the process lock.
    // SMAP discipline (Intel SDM Vol. 3A §4.6): the four `*(new_val_ptr + N)`
    // dereferences below target a user-mapped page (PTE.U=1); without
    // EFLAGS.AC=1 they fault and our handler escalates to KERNEL_PAGE_FAULT.
    // UserGuard sets AC on construction and clears on drop / panic-unwind.
    let (new_interval_ticks, new_value_ticks) = if new_val_ptr != 0 {
        if !crate::syscall::validate_user_ptr(new_val_ptr, 32) { return -14; } // EFAULT
        let (it_interval_sec, it_interval_usec, it_value_sec, it_value_usec) = unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            (
                *( new_val_ptr       as *const i64) as u64,
                *((new_val_ptr + 8)  as *const i64) as u64,
                *((new_val_ptr + 16) as *const i64) as u64,
                *((new_val_ptr + 24) as *const i64) as u64,
            )
        };
        // Convert microseconds → ticks (round up, minimum 1 if non-zero).
        let interval_us = it_interval_sec * 1_000_000 + it_interval_usec;
        let value_us    = it_value_sec    * 1_000_000 + it_value_usec;
        let interval_ticks = if interval_us == 0 { 0 } else { (interval_us * TICKS_PER_SEC / 1_000_000).max(1) };
        let value_ticks    = if value_us    == 0 { 0 } else { (value_us    * TICKS_PER_SEC / 1_000_000).max(1) };
        (interval_ticks, value_ticks)
    } else {
        return -14; // EFAULT: new_value is mandatory for setitimer
    };

    let mut procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    // Optionally return the old timer value.
    if old_val_ptr != 0 && crate::syscall::validate_user_ptr(old_val_ptr, 32) {
        let old_remaining_ticks = if proc.alarm_deadline_ticks > now {
            proc.alarm_deadline_ticks - now
        } else {
            0
        };
        let old_value_us    = old_remaining_ticks * 1_000_000 / TICKS_PER_SEC;
        let old_interval_us = proc.alarm_interval_ticks * 1_000_000 / TICKS_PER_SEC;
        // SMAP guard — kernel→user writes to itimerval-out struct.
        unsafe {
            let _g = crate::arch::x86_64::smap::UserGuard::new();
            // it_interval
            *( old_val_ptr       as *mut i64) = (old_interval_us / 1_000_000) as i64;
            *((old_val_ptr +  8) as *mut i64) = (old_interval_us % 1_000_000) as i64;
            // it_value
            *((old_val_ptr + 16) as *mut i64) = (old_value_us / 1_000_000) as i64;
            *((old_val_ptr + 24) as *mut i64) = (old_value_us % 1_000_000) as i64;
        }
    }

    // Arm the new timer.
    if new_value_ticks == 0 {
        proc.alarm_deadline_ticks = 0; // disarm
        proc.alarm_interval_ticks = 0;
    } else {
        proc.alarm_deadline_ticks = now + new_value_ticks;
        proc.alarm_interval_ticks = new_interval_ticks;
    }
    0
}

/// getitimer(which, curr_value) — read current ITIMER_REAL state.
fn sys_getitimer(which: u64, val_ptr: u64) -> i64 {
    const ITIMER_REAL: u64 = 0;
    if which != ITIMER_REAL {
        return -22; // EINVAL
    }
    if val_ptr == 0 || !crate::syscall::validate_user_ptr(val_ptr, 32) {
        return -14; // EFAULT
    }
    let pid = crate::proc::current_pid_lockless();
    let now = crate::arch::x86_64::irq::get_ticks();
    let procs = crate::proc::PROCESS_TABLE.lock();
    let proc = match procs.iter().find(|p| p.pid == pid) {
        Some(p) => p,
        None => return -3,
    };
    let remaining_ticks = if proc.alarm_deadline_ticks > now {
        proc.alarm_deadline_ticks - now
    } else {
        0
    };
    let value_us    = remaining_ticks * 1_000_000 / TICKS_PER_SEC;
    let interval_us = proc.alarm_interval_ticks * 1_000_000 / TICKS_PER_SEC;
    // SMAP guard — kernel→user write to itimerval-out struct
    // (Intel SDM Vol. 3A §4.6; getitimer(2)).
    unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        *( val_ptr       as *mut i64) = (interval_us / 1_000_000) as i64;
        *((val_ptr +  8) as *mut i64) = (interval_us % 1_000_000) as i64;
        *((val_ptr + 16) as *mut i64) = (value_us / 1_000_000) as i64;
        *((val_ptr + 24) as *mut i64) = (value_us % 1_000_000) as i64;
    }
    0
}

/// Resolve a path relative to `dirfd` (or CWD when dirfd == AT_FDCWD).
/// Returns the full absolute path as an owned String, or an errno on error.
fn resolve_at_path(dirfd: u64, rel_ptr: u64) -> Result<alloc::string::String, i64> {
    const AT_FDCWD: i64 = -100;
    let path_bytes = read_cstring_from_user(rel_ptr);
    let rel_str = core::str::from_utf8(&path_bytes).map_err(|_| -22i64)?;
    if rel_str.is_empty() {
        return Err(-2); // ENOENT
    }
    // Absolute path: dirfd is irrelevant (POSIX).
    if rel_str.starts_with('/') {
        return Ok(alloc::string::String::from(rel_str));
    }
    // Relative path with AT_FDCWD: use process CWD.
    if dirfd as i64 == AT_FDCWD {
        let pid = crate::proc::current_pid_lockless();
        let procs = crate::proc::PROCESS_TABLE.lock();
        let cwd = procs.iter().find(|p| p.pid == pid)
            .map(|p| p.cwd.clone())
            .unwrap_or_else(|| alloc::string::String::from("/"));
        drop(procs);
        return Ok(if cwd.ends_with('/') {
            alloc::format!("{}{}", cwd, rel_str)
        } else {
            alloc::format!("{}/{}", cwd, rel_str)
        });
    }
    // Relative path with a real directory fd: get dir path from fd table.
    let pid = crate::proc::current_pid_lockless();
    let dir_path = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc = procs.iter().find(|p| p.pid == pid).ok_or(-3i64)?;
        let fd_idx = dirfd as usize;
        proc.file_descriptors.get(fd_idx)
            .and_then(|f| f.as_ref())
            .map(|f| f.open_path.clone())
            .ok_or(-9i64)? // EBADF
    };
    Ok(if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, rel_str)
    } else {
        alloc::format!("{}/{}", dir_path, rel_str)
    })
}

/// mkdirat(dirfd, pathname, mode) — create directory relative to dirfd.
fn sys_mkdirat(dirfd: u64, pathname: u64, _mode: u64) -> i64 {
    let full_path = match resolve_at_path(dirfd, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match crate::vfs::mkdir(&full_path) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// unlinkat(dirfd, pathname, flags) — remove file or directory relative to dirfd.
///
/// AT_REMOVEDIR (0x200) causes rmdir semantics; otherwise unlink.
fn sys_unlinkat(dirfd: u64, pathname: u64, flags: u64) -> i64 {
    const AT_REMOVEDIR: u64 = 0x200;
    let full_path = match resolve_at_path(dirfd, pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if flags & AT_REMOVEDIR != 0 {
        let path_bytes = full_path.as_bytes();
        crate::syscall::sys_rmdir(path_bytes.as_ptr(), path_bytes.len())
    } else {
        let path_bytes = full_path.as_bytes();
        crate::syscall::sys_unlink(path_bytes.as_ptr(), path_bytes.len())
    }
}

/// renameat(olddirfd, oldpath, newdirfd, newpath) — rename relative to dir fds.
fn sys_renameat(olddirfd: u64, oldpath: u64, newdirfd: u64, newpath: u64) -> i64 {
    let old = match resolve_at_path(olddirfd, oldpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new = match resolve_at_path(newdirfd, newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match crate::vfs::rename(&old, &new) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags) — create a hard link
/// relative to directory fds.  Implements POSIX/Linux `linkat(2)`.
///
/// `flags` may carry `AT_SYMLINK_FOLLOW` (0x400) — follow a trailing symlink
/// in `oldpath` — and `AT_EMPTY_PATH` (0x1000).  AstryxOS' `vfs::link` does
/// not follow a trailing symlink (it links the named object itself); since
/// the dominant caller (fontconfig's `link(TMP, LCK)`) links a regular file,
/// not a symlink, both behaviours coincide and the flags are accepted but
/// have no observable effect here.  Unknown flag bits are rejected (EINVAL).
fn sys_linkat(olddirfd: u64, oldpath: u64, newdirfd: u64, newpath: u64, flags: u64) -> i64 {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return -22; // EINVAL
    }
    let old = match resolve_at_path(olddirfd, oldpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new = match resolve_at_path(newdirfd, newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match crate::vfs::link(&old, &new) {
        Ok(()) => 0,
        Err(e) => crate::subsys::linux::errno::vfs_err(e),
    }
}

/// getdents(fd, buf, count) — 32-bit inode/offset variant of getdents64.
///
/// struct linux_dirent layout (NOT linux_dirent64):
///   d_ino:    u32  @0   — inode number (truncated to 32 bits)
///   d_off:    u32  @4   — offset to next entry (truncated to 32 bits)
///   d_reclen: u16  @8   — total record length including name and padding
///   d_name:   char @10  — null-terminated filename
///   (d_type is stored as the byte just before the null terminator, after the name)
///
/// Per man 2 getdents: d_type is at offset d_reclen-1 (last byte of the record).
fn sys_getdents(fd: u64, buf: u64, count: u64) -> i64 {
    let pid = crate::proc::current_pid_lockless();
    let (mount_idx, inode, offset) = {
        let procs = crate::proc::PROCESS_TABLE.lock();
        let proc_entry = match procs.iter().find(|p| p.pid == pid) {
            Some(p) => p,
            None => return -3,
        };
        let fd_entry = match proc_entry.file_descriptors.get(fd as usize).and_then(|f| f.as_ref()) {
            Some(f) => f,
            None => return -9,
        };
        (fd_entry.mount_idx, fd_entry.inode, fd_entry.offset)
    };

    // Snapshot Arc<FS> under MOUNTS, drop the lock, then dispatch readdir().
    // Same reasoning as the getdents64 path above: block I/O in readdir may
    // call schedule(), so MOUNTS must not be held across the dispatch.
    let entries = match crate::vfs::fs_at(mount_idx) {
        Some((fs, _)) => match fs.readdir(inode) {
            Ok(e) => e,
            Err(e) => return crate::subsys::linux::errno::vfs_err(e),
        },
        None => return -9,
    };

    if buf == 0 || !crate::syscall::validate_user_ptr(buf, count as usize) {
        return -14; // EFAULT
    }
    // SMAP bracket — `buf` is a user-VA pointer.
    let _smap_g = unsafe { crate::arch::x86_64::smap::UserGuard::new() };
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
    let mut pos = 0usize;
    let mut entry_idx = offset as usize;

    while entry_idx < entries.len() {
        let (ref name, ino, ft) = entries[entry_idx];
        let name_bytes = name.as_bytes();
        // Record: 4(d_ino) + 4(d_off) + 2(d_reclen) + name + 1(d_type) + 1(nul)
        // Padded to 4-byte alignment (32-bit ABI compatibility).
        let fixed = 12 + name_bytes.len() + 1; // header + name + d_type byte (at end)
        let reclen = (fixed + 3) & !3; // align to 4 bytes

        if pos + reclen > count as usize {
            break;
        }

        let d_ino = ino as u32;
        let d_off = (entry_idx + 1) as u32;
        let d_type: u8 = match ft {
            crate::vfs::FileType::RegularFile => 8,  // DT_REG
            crate::vfs::FileType::Directory   => 4,  // DT_DIR
            crate::vfs::FileType::SymLink     => 10, // DT_LNK
            crate::vfs::FileType::CharDevice  => 2,  // DT_CHR
            crate::vfs::FileType::BlockDevice => 6,  // DT_BLK
            _                                 => 0,  // DT_UNKNOWN
        };

        // d_ino (u32 @0)
        out[pos..pos+4].copy_from_slice(&d_ino.to_le_bytes());
        // d_off (u32 @4)
        out[pos+4..pos+8].copy_from_slice(&d_off.to_le_bytes());
        // d_reclen (u16 @8)
        out[pos+8..pos+10].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_name (@10): name bytes then d_type then null terminator
        let nlen = name_bytes.len().min(reclen - 12);
        out[pos+10..pos+10+nlen].copy_from_slice(&name_bytes[..nlen]);
        // Zero padding between name and the end of the record
        for i in (pos+10+nlen)..(pos+reclen-1) {
            out[i] = 0;
        }
        // d_type stored as last byte of record (glibc/musl convention)
        out[pos+reclen-1] = d_type;

        pos += reclen;
        entry_idx += 1;
    }

    // Update fd offset.
    {
        let mut procs = crate::proc::PROCESS_TABLE.lock();
        if let Some(proc_entry) = procs.iter_mut().find(|p| p.pid == pid) {
            if let Some(Some(fd_entry)) = proc_entry.file_descriptors.get_mut(fd as usize) {
                fd_entry.offset = entry_idx as u64;
            }
        }
    }
    pos as i64
}

/// preadv(fd, iov, iovcnt, offset) — scatter-gather positioned read.
///
/// Reads from position `offset` (does not advance the fd offset) into the
/// iovec array.  Per POSIX, the file offset is preserved after the call.
fn sys_preadv(fd: u64, iov_ptr: u64, iovcnt: u64, offset: i64) -> i64 {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; } // EINVAL: IOV_MAX
    // CWE-823: range-validate iov_ptr (see sys_writev for full rationale).
    if !crate::syscall::validate_user_ptr(iov_ptr, (iovcnt as usize).saturating_mul(16)) {
        return -14; // EFAULT
    }
    let pid = crate::proc::current_pid_lockless();
    // Save, seek to offset, scatter-read, restore.
    let saved = crate::syscall::sys_lseek(fd as usize, 0, 1 /*SEEK_CUR*/);
    let sk = crate::syscall::sys_lseek(fd as usize, offset, 0 /*SEEK_SET*/);
    if sk < 0 { return sk; }
    // SAFETY: iov_ptr range-validated above; iov_base/iov_len validated by
    // the per-iov fd_read path (vfs handles short reads).  SMAP-bracketed
    // copy into kernel Vec so the loop reads the descriptor table from
    // kernel memory.
    let iovecs_owned: alloc::vec::Vec<[u64; 2]> = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iovcnt as usize).to_vec()
    };
    let mut total = 0i64;
    for iov in &iovecs_owned {
        let base = iov[0];
        let len  = iov[1] as usize;
        if len == 0 { continue; }
        let result = match crate::vfs::fd_read(pid, fd as usize, base as *mut u8, len) {
            Ok(n) => n as i64,
            Err(e) => {
                if total > 0 { break; }
                if saved >= 0 { let _ = crate::syscall::sys_lseek(fd as usize, saved, 0); }
                return crate::subsys::linux::errno::vfs_err(e);
            }
        };
        total += result;
        if (result as usize) < len { break; } // short read — stop
    }
    if saved >= 0 { let _ = crate::syscall::sys_lseek(fd as usize, saved, 0); }
    total
}

/// pwritev(fd, iov, iovcnt, offset) — scatter-gather positioned write.
///
/// Writes from the iovec array to position `offset`.  The fd offset is
/// preserved after the call (same contract as pread64).
fn sys_pwritev(fd: u64, iov_ptr: u64, iovcnt: u64, offset: i64) -> i64 {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; } // EINVAL: IOV_MAX
    // CWE-823: range-validate iov_ptr (see sys_writev for full rationale).
    if !crate::syscall::validate_user_ptr(iov_ptr, (iovcnt as usize).saturating_mul(16)) {
        return -14; // EFAULT
    }
    let pid = crate::proc::current_pid_lockless();
    let saved = crate::syscall::sys_lseek(fd as usize, 0, 1 /*SEEK_CUR*/);
    let sk = crate::syscall::sys_lseek(fd as usize, offset, 0 /*SEEK_SET*/);
    if sk < 0 { return sk; }
    // SAFETY: iov_ptr range-validated above; iov_base/iov_len reach fd_write
    // via the vfs which handles short writes.  SMAP-bracketed copy.
    let iovecs_owned: alloc::vec::Vec<[u64; 2]> = unsafe {
        let _g = crate::arch::x86_64::smap::UserGuard::new();
        core::slice::from_raw_parts(iov_ptr as *const [u64; 2], iovcnt as usize).to_vec()
    };
    let mut total = 0i64;
    for iov in &iovecs_owned {
        let base = iov[0];
        let len  = iov[1] as usize;
        if len == 0 { continue; }
        let result = match crate::vfs::fd_write(pid, fd as usize, base as *const u8, len) {
            Ok(n) => n as i64,
            Err(e) => {
                if total > 0 { break; }
                if saved >= 0 { let _ = crate::syscall::sys_lseek(fd as usize, saved, 0); }
                return crate::subsys::linux::errno::vfs_err(e);
            }
        };
        total += result;
    }
    if saved >= 0 { let _ = crate::syscall::sys_lseek(fd as usize, saved, 0); }
    total
}

// ── Phase 3B: user-stack snapshot helper ────────────────────────────────────
//
// Walks the saved RBP frame chain in user space starting from the user RBP
// captured at syscall entry, emits up to 16 RIPs (in addition to the leaf
// RIP captured by [SC]), and quits at the first invalid frame.
//
// All reads use `virt_to_phys_in` against the calling process's CR3 so a
// corrupt RBP returns 0 instead of faulting.  RBP=0 (or non-canonical user
// range) terminates the walk cleanly.
//
// Frame layout per System V x86_64 ABI (AMD64 ABI §3.4) with frame pointers:
//   [rbp]    = saved caller RBP
//   [rbp+8]  = saved return RIP
//
// Output format (one line per snapshot):
//   [SC-USTACK] pid=<n> tid=<n> nr=<num> n=<sample-index> rsp=<...> rbp=<...>
//               leaf=<rip0> f1=<rip1> f2=<rip2> ... f15=<rip15>
//
// The host post-processor pairs each `f<i>=` against the [FFTEST/mmap-so]
// load-base table to resolve every frame to <library> + offset, then runs
// `nm` / `addr2line` for symbolisation.  The walk terminates early when
// frame pointers are omitted (common in JIT code), which is harmless —
// we still get the leaf, the libc-wrapper caller (`cr=` in [SC]), and as
// many native frames as the compiler preserved.
#[cfg(all(feature = "firefox-test-core", feature = "firefox-trace-verbose"))]
fn emit_user_stack_snapshot(num: u64, sample_idx: u64) {
    use core::fmt::Write as _;
    const PHYS_OFF: u64 = 0xFFFF_8000_0000_0000;
    const MAX_FRAMES: usize = 16;

    let pid = crate::proc::current_pid_lockless();
    let tid = crate::proc::current_tid();
    let (user_rsp, user_rbp) = crate::syscall::get_user_rsp_rbp();
    let leaf_rip = unsafe { crate::syscall::get_user_rip() };
    let cr3 = crate::mm::vmm::get_cr3();

    // Plausible user-VA bounds — anything outside aborts the walk.
    let user_ok = |va: u64| -> bool {
        va >= 0x1000 && va < astryx_shared::KERNEL_VIRT_BASE && (va & 0x7) == 0
    };

    // Read 8 bytes from user space, returning None on bad address.  Uses
    // `virt_to_phys_in` so an unmapped page just returns None (no fault).
    let read_u64 = |va: u64| -> Option<u64> {
        if !user_ok(va) { return None; }
        let phys = crate::mm::vmm::virt_to_phys_in(cr3, va)?;
        // SAFETY: phys is a valid frame returned by the page-table walk;
        // PHYS_OFF + phys is mapped in the kernel's higher-half identity
        // region for all RAM, so the unaligned 8-byte read cannot fault.
        Some(unsafe { core::ptr::read_unaligned((PHYS_OFF + phys) as *const u64) })
    };

    // 1024 chosen so a fully-populated snapshot (16 RBP frames × ~12 bytes
    // each + 16 stack-scan candidates × ~22 bytes each + the ~80-byte
    // header) fits without a realloc.  Previous 512-byte capacity always
    // grew at least once on full snapshots, which is wasteful when the
    // formatter is on the hot busy-poll path.
    let mut line = alloc::string::String::with_capacity(1024);
    let _ = write!(
        &mut line,
        "[SC-USTACK] pid={} tid={} nr={} n={} rsp={:#x} rbp={:#x} leaf={:#x}",
        pid, tid, num, sample_idx, user_rsp, user_rbp, leaf_rip
    );

    let mut rbp = user_rbp;
    let mut frames_emitted = 0usize;
    for i in 0..MAX_FRAMES {
        if !user_ok(rbp) { break; }
        let saved_rbp = match read_u64(rbp)     { Some(v) => v, None => break };
        let saved_rip = match read_u64(rbp + 8) { Some(v) => v, None => break };
        let _ = write!(&mut line, " f{}={:#x}", i + 1, saved_rip);
        frames_emitted += 1;
        // Ascending stack with RBP_new > RBP_old; if rbp regresses or
        // doesn't move we treat the chain as corrupted and stop.
        if saved_rbp <= rbp { break; }
        rbp = saved_rbp;
    }

    // Frame-pointer walk often terminates early because libnspr4 / libxul are
    // built with `-fomit-frame-pointer` for tier-1 perf.  Fall back to a
    // bounded conservative stack-word scan above RSP, emitting at most 16
    // additional candidate return-addresses.  The host post-processor filters
    // by `[FFTEST/mmap-so]` exec range so the noise is bounded.
    //
    // Format: ` s<i>=<rsp_offset>:<word>` — host can keep words pointing
    // into known exec ranges as candidate frames.
    if frames_emitted < MAX_FRAMES {
        // Stack-scan pre-filter range — the user-space mmap window where the
        // dynamic loader places shared objects, the heap, and per-thread
        // stacks.  Defined as a named constant so a future change to the
        // mmap policy (mm::vma::USER_MMAP_BASE etc.) can be tracked back to
        // a single source of truth.  See the user-VA layout documented in
        // `kernel/src/mm/vma.rs` (USER_MMAP_BASE..KERNEL_VIRT_BASE).
        const USER_EXEC_VA_LO: u64 = 0x7000_0000_0000;
        const USER_EXEC_VA_HI: u64 = 0x8000_0000_0000;

        let mut emitted_scan = 0usize;
        let scan_words = 256usize; // 2 KiB of stack above RSP
        for off in 0..scan_words {
            if emitted_scan >= 16 { break; }
            let va = user_rsp.wrapping_add((off as u64) * 8);
            let w = match read_u64(va) { Some(v) => v, None => break };
            // Only print words that look like a user-space code address —
            // host filtering by exec-range handles the rest.
            if w >= USER_EXEC_VA_LO && w < USER_EXEC_VA_HI {
                let _ = write!(&mut line, " s{}={:#x}:{:#x}",
                    emitted_scan, off * 8, w);
                emitted_scan += 1;
            }
        }
    }

    crate::serial_println!("{}", line);
}
