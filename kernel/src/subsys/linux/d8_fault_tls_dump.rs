//! D8 fault-time TLS slot dump + phys-frame provenance.
//!
//! ## What this catches
//!
//! Phase 8 of the sc=1171 investigation (after PR #371 D7) reproduced
//! the byte-identical pid=1 firefox-bin NULL deref on plain post-PR-#370
//! master.  D7's DR-watchpoint on `[fs:-0x18]` captured **zero writes**
//! across all observed trials, falsifying the "writer mutated the slot
//! after install" framing (PSE hypotheses Z2 and Z3).  What remains as
//! the dominant survivor is **Z1**: the TLS slot is non-zero at *first*
//! access because the anon-mmap that backs the PT_TLS segment returned a
//! recycled physical frame **without** the ELF gABI §5.2 zero-fill
//! contract being honoured (CWE-908 — Use of Uninitialized Resource).
//!
//! D8 takes the orthogonal angle to D7: rather than catching a *write*,
//! it inspects the slot **at fault time** (the very instant Mozilla's
//! `GetThreadRegistrationTime` reaches the NULL deref) and reports:
//!
//!   * the current value of the qword at `[fs:-0x18]` — the smoking
//!     gun: if it is zero, Z1 is falsified and the framing must be
//!     re-derived; if it is non-zero, Z1 survives;
//!   * the physical frame backing that VA — phys-anchored attribution
//!     per the saga-discipline Rule 1;
//!   * `FREE_SHADOW` and `ALLOC_SHADOW` lookups on that phys frame —
//!     names the most recent `pmm::free_page` and `pmm::alloc_page`
//!     caller RIPs for the backing frame, so a Z1-positive verdict
//!     points directly at the recycle path.
//!
//! ## Content-gate (no offset-gate, no name-gate)
//!
//! Per saga-discipline Rule 2 (avoid rotted symbolic invariants), the
//! D8 fingerprint is **content-anchored** on three values that are
//! constant across the three byte-identical Phase 7/8 trials documented
//! in `docs/SC1171_PSE_END_TO_END_2026-05-22.md`:
//!
//!   1. `cr2 == 0x20` — the offset into the (NULL) `r14` pointer that
//!      `mov 0x20(%r14), %rbx` derefs;
//!   2. opcode at RIP starts with the byte sequence `49 8b 5e 20`
//!      (`mov 0x20(%r14), %rbx`, the exact instruction Mozilla emits at
//!      `firefox-bin + 0x207dc`), validated by reading 4 user bytes
//!      through the kernel direct map;
//!   3. `pid == 1` — firefox-bin under the Linux personality.
//!
//! All three matching narrows to the sc=1171 fingerprint and excludes
//! coincidental CR2=0x20 faults from other pids or other instructions
//! that happen to land at CR2=0x20 (e.g. a `mov 0x20(%rbx), …` with rbx
//! NULL would have opcode bytes `48 8b 5b 20`, distinct from
//! `49 8b 5e 20`).
//!
//! ## One-shot semantics
//!
//! `D8_FIRE_MAX = 1` — the first matching fault disarms the dump.  The
//! sc=1171 fingerprint is deterministic, so a single capture is
//! dispositive; the cap prevents log flood if a non-deterministic
//! recurrence ever fires.
//!
//! ## No-fix discipline
//!
//! Per saga-discipline Rule 1, this module is read-only: no page-table
//! mutation, no frame allocation, no lock-order changes.  All emitted
//! data goes to serial via `serial_println!`, and the underlying reads
//! all go through the kernel direct-map.
//!
//! ## Refs
//!
//!   * Intel SDM Vol. 3A §3.4.4 (TLS via `IA32_FS_BASE`);
//!   * Intel SDM Vol. 3A §4.10.5 (paging-structure caches);
//!   * Intel SDM Vol. 2A §2.1 (Instruction Format);
//!   * ELF gABI §5.2 (PT_TLS `memsz > filesz` zero-fill);
//!   * POSIX `mmap(2)` (anonymous-mapping zero-fill on first access);
//!   * CWE-908 (Use of Uninitialized Resource);
//!   * CWE-401 (Missing Release of Memory after Effective Lifetime).

#![cfg(feature = "d8-tls-fault-dump")]

use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of fault-time dumps per boot.  Single-shot:
/// fingerprint is deterministic, one capture is dispositive.
const D8_FIRE_MAX: u32 = 1;

/// Per-boot fire counter.  Bumped only on a fully matched fingerprint.
static D8_FIRE_COUNT: AtomicU32 = AtomicU32::new(0);

/// CR2 value to match: `mov 0x20(%r14), %rbx` with `r14 = NULL` faults
/// at CR2=0x20 per Intel SDM Vol. 3A §4.7.  The PSE Phase 7 byte-
/// perfect 3/3 trials confirm this is the deterministic sc=1171 CR2.
const D8_MATCH_CR2: u64 = 0x20;

/// Target pid: firefox-bin under the Linux personality is always pid=1
/// in the firefox-test build.
const D8_MATCH_PID: u64 = 1;

/// First four opcode bytes of `mov 0x20(%r14), %rbx`:
///   `49`  — REX.W=1 + REX.B=1 (extends ModR/M `r/m` to r14)
///   `8b`  — `MOV r64, r/m64`
///   `5e`  — ModR/M: mod=01 (disp8), reg=011 (rbx), r/m=110 (r14)
///   `20`  — disp8 = +0x20
/// Per Intel SDM Vol. 2A §2.1 (Instruction Format).  This byte
/// sequence is the **content-gate** — any rotation of the instruction
/// (different displacement, different destination register, different
/// base) would change at least one byte and fail the match.
const D8_OPCODE_PREFIX: [u8; 4] = [0x49, 0x8b, 0x5e, 0x20];

/// TLS-slot offset from `fs_base`.  Matches D7's
/// `TLS_SLOT_OFFSET_FROM_FS_BASE`: the suspect qword at
/// `[fs:-0x18]` is the BSS slot Mozilla's `GetThreadRegistrationTime`
/// reads as the `RegisteredThread*` source.
const D8_TLS_SLOT_OFFSET: u64 = 0x18;

/// Fault-immune qword read of a user VA through the kernel direct
/// map.  Returns `Some((value, phys))` if the user page is present
/// under the current CR3, `None` otherwise.  Read goes through the
/// kernel direct physical map — never faults on a not-present **user**
/// PTE, because the actual load address is a kernel VA whose phys
/// backing was confirmed by `virt_to_phys_in`.
///
/// Rejects reads that would straddle a 4 KiB boundary: per Intel SDM
/// Vol. 3A §4.6, an 8-byte access straddles only when
/// `(addr & 0xFFF) > 0x1000 - 8`; in that case `None` is returned.
fn read_user_qword(addr: u64) -> Option<(u64, u64)> {
    if !crate::syscall::validate_user_ptr(addr, 8) { return None; }
    if (addr & 0xFFF) > 0x1000 - 8 { return None; }
    let cr3 = crate::mm::vmm::get_cr3();
    let phys = crate::mm::vmm::virt_to_phys_in(cr3, addr)?;
    let val = unsafe {
        core::ptr::read_volatile((crate::mm::vmm::PHYS_OFF + phys) as *const u64)
    };
    Some((val, phys))
}

/// Read the first 4 bytes of the instruction at the faulting RIP.
/// Used by the D8 content-gate to confirm the opcode is the
/// `49 8b 5e 20` prefix of `mov 0x20(%r14), %rbx`.
fn read_user_bytes_4(addr: u64) -> Option<[u8; 4]> {
    let (qword, _phys) = read_user_qword(addr)?;
    let bytes = qword.to_le_bytes();
    Some([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Hook invoked from `idt::handle_exception` on a fatal user-mode #PF
/// (the `error_code & 4 != 0` path, after `handle_page_fault` returns
/// false and before `deliver_sigsegv_from_isr`).
///
/// Arguments are everything D8 needs from the trap frame; the call
/// site reads them once and passes them in so the hook stays a single
/// unconditional call.
///
/// All gating decisions happen inside this function: a non-matching
/// fault returns early without emitting any output, so the call site
/// pays only one function call + one `AtomicU32::load` on the common
/// non-fingerprint path.
pub fn try_dump_at_fault(
    cr2: u64,
    rip: u64,
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8:  u64, r9:  u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
    pid: u64, tid: u64,
) {
    // ── Gate 1: CR2 ──
    if cr2 != D8_MATCH_CR2 { return; }

    // ── Gate 2: pid ──
    if pid != D8_MATCH_PID { return; }

    // ── Gate 3: opcode content at RIP ──
    let opcode = match read_user_bytes_4(rip) {
        Some(b) => b,
        None    => return,  // unreadable RIP: not our fingerprint
    };
    if opcode != D8_OPCODE_PREFIX { return; }

    // ── One-shot claim ──
    // Use compare_exchange to ensure exactly one matching fault
    // produces output, even under (hypothetical) concurrent fault
    // delivery on multiple CPUs.
    let prev = D8_FIRE_COUNT.load(Ordering::Relaxed);
    if prev >= D8_FIRE_MAX { return; }
    if D8_FIRE_COUNT
        .compare_exchange(prev, prev + 1, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;  // a sibling beat us; their dump will cover the case
    }

    // ── Read FS.base (Intel SDM Vol. 3A §3.4.4.1) ──
    const IA32_FS_BASE: u32 = 0xC000_0100;
    let fs_base = unsafe { crate::hal::rdmsr(IA32_FS_BASE) };

    let cpu = crate::arch::x86_64::apic::cpu_index();

    // ── Header ──
    crate::serial_println!(
        "[D8/FAULT-DUMP] pid={} tid={} cpu={} cr2={:#x} rip={:#x} fs_base={:#x}",
        pid, tid, cpu, cr2, rip, fs_base,
    );

    // ── Register snapshot — full 16 user GPRs ──
    // Helps cross-check against PSE Phase 7 byte-perfect captures
    // (r14=0, r8=0xfefefefefefefeff musl-tombstone, rbp=0x9, etc.).
    crate::serial_println!(
        "[D8/FAULT-DUMP] gpr rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
        rax, rbx, rcx, rdx,
    );
    crate::serial_println!(
        "[D8/FAULT-DUMP] gpr rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}",
        rsi, rdi, rbp, rsp,
    );
    crate::serial_println!(
        "[D8/FAULT-DUMP] gpr r8 ={:#018x} r9 ={:#018x} r10={:#018x} r11={:#018x}",
        r8, r9, r10, r11,
    );
    crate::serial_println!(
        "[D8/FAULT-DUMP] gpr r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}",
        r12, r13, r14, r15,
    );

    // ── The smoking gun: value at [fs:-0x18] AT FAULT TIME ──
    // If r14==0 came from this slot (per PSE Phase 2 disassembly),
    // this is the value that turned the early-return into the slow
    // path.  Zero ⇒ Z1 falsified.  Non-zero ⇒ Z1 candidate.
    if fs_base < D8_TLS_SLOT_OFFSET {
        // Emit shadow totals before bailing so a post-processor sees how
        // many free/alloc events were recorded prior to the fault; helps
        // disambiguate "no provenance because rings were empty" from
        // "no provenance because we returned early before lookup".
        let fr = crate::mm::w215_diag::free_shadow_recorded_count();
        let ar = crate::mm::w215_diag::alloc_shadow_recorded_count();
        crate::serial_println!(
            "[D8/FAULT-DUMP] tls_slot fs_base_too_small fs_base={:#x} \
             free_recorded={} alloc_recorded={}",
            fs_base, fr, ar,
        );
        return;
    }
    let tls_va = fs_base - D8_TLS_SLOT_OFFSET;
    let cr3 = crate::mm::vmm::get_cr3();
    let tls_phys = crate::mm::vmm::virt_to_phys_in(cr3, tls_va);
    let tls_val = read_user_qword(tls_va).map(|(v, _p)| v);
    match (tls_val, tls_phys) {
        (Some(v), Some(p)) => crate::serial_println!(
            "[D8/FAULT-DUMP] tls_at_fs_minus_0x18 va={:#x} val={:#018x} phys={:#x}",
            tls_va, v, p,
        ),
        (Some(v), None) => crate::serial_println!(
            "[D8/FAULT-DUMP] tls_at_fs_minus_0x18 va={:#x} val={:#018x} phys=?",
            tls_va, v,
        ),
        (None, _) => crate::serial_println!(
            "[D8/FAULT-DUMP] tls_at_fs_minus_0x18 va={:#x} val=? phys=?",
            tls_va,
        ),
    }

    // ── TLS-region context: 8 qwords on each side of fs_base ──
    // Lets a post-processor see whether the BSS tail looks like a
    // recycled heap arena (non-zero pointer-shaped values) vs a
    // freshly-zeroed page (all zeros).  Per ELF gABI §5.2 the entire
    // PT_TLS BSS tail should read zero on first access.
    //
    // Emitted as a single multi-line `serial_println!` so the 16 rows
    // cannot be interleaved with output from a concurrent CPU's serial
    // writer (the underlying serial layer serialises per-call but does
    // not lock across separate `serial_println!` invocations).
    //
    // `Some(0)` is encoded as `0x0000000000000000`; `None` (read failed
    // — page not mapped under the current CR3) is encoded as `?` so the
    // post-processor can distinguish "zero value" from "unreadable".
    let mut vals: [Option<u64>; 16] = [None; 16];
    for (idx, q) in (-8i64..8i64).enumerate() {
        let va = (fs_base as i64 + q * 8) as u64;
        vals[idx] = read_user_qword(va).map(|(v, _)| v);
    }
    let fmt = |o: Option<u64>| -> [u8; 18] {
        // 18 chars: "0x" + 16 hex digits, or "?" right-padded.  Returned
        // as a stack array so the closure has no allocation footprint.
        let mut buf = [b' '; 18];
        match o {
            Some(v) => {
                buf[0] = b'0'; buf[1] = b'x';
                for i in 0..16 {
                    let nyb = ((v >> (60 - i * 4)) & 0xf) as u8;
                    buf[2 + i] = if nyb < 10 { b'0' + nyb } else { b'a' + nyb - 10 };
                }
            }
            None => { buf[0] = b'?'; }
        }
        buf
    };
    // Convert to &str via from_utf8_unchecked: all bytes above are ASCII
    // hex / space / '?' / 'x' so UTF-8-validity holds by construction.
    let s: [[u8; 18]; 16] = core::array::from_fn(|i| fmt(vals[i]));
    let r: [&str; 16] = core::array::from_fn(|i| {
        // SAFETY: `fmt` only writes ASCII bytes.
        unsafe { core::str::from_utf8_unchecked(&s[i]) }
    });
    crate::serial_println!(
        "[D8/FAULT-DUMP] tls_dump fs_base-0x40: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x38: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x30: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x28: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x20: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x18: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x10: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base-0x8:  {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x0:  {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x8:  {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x10: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x18: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x20: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x28: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x30: {}\n\
         [D8/FAULT-DUMP] tls_dump fs_base+0x38: {}",
        r[0], r[1], r[2],  r[3],  r[4],  r[5],  r[6],  r[7],
        r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15],
    );

    // ── Phys-frame provenance: FREE_SHADOW + ALLOC_SHADOW ──
    // Both rings are direct-addressed by `pfn & (SIZE-1)`, so a hit
    // is "the most recent free/alloc with that PFN-low-bits prefix".
    // On collision the newer entry overwrote the older — for sc=1171
    // the slot of interest is the most recently freed frame matching
    // tls_phys, so a hit names a candidate.  Per saga-discipline
    // Rule 5 (cross-tool symbolisation), the recorded RIP is the
    // kernel-side caller of `pmm::free_page` / `pmm::alloc_page`,
    // resolvable via `addr2line` against the kernel ELF.
    if let Some(phys) = tls_phys {
        crate::mm::w215_diag::dump_free_shadow_for_phys(phys);
        crate::mm::w215_diag::dump_alloc_shadow_for_phys(phys);
        let fr = crate::mm::w215_diag::free_shadow_recorded_count();
        let ar = crate::mm::w215_diag::alloc_shadow_recorded_count();
        crate::serial_println!(
            "[D8/FAULT-DUMP] shadow_totals free_recorded={} alloc_recorded={}",
            fr, ar,
        );
    } else {
        crate::serial_println!(
            "[D8/FAULT-DUMP] phys_lookup_failed va={:#x} cr3={:#x}",
            tls_va, cr3,
        );
    }

    // ── D10: HEAP-OBJECT phys-provenance (Phase-2-E closer) ──
    //
    // The TLS slot at `[fs:-0x18]` holds a pointer to a heap-resident
    // `RegisteredThread` object; Mozilla's `GetThreadRegistrationTime`
    // loads that pointer into `r14` and then derefs `0x20(%r14)` (the
    // `mThreadInfo` field).  Phase 2-A/B/C/D cleanly excluded heap-alloc
    // zero-fill, ctor codegen elision, signal preemption, and
    // unregistered-caller framings.  The one residual is whether the
    // heap *page* itself (not the TLS slot's page) was the target of a
    // recent `pmm::free_page` / `pmm::alloc_page` recycle that left the
    // outer object with a partial-zero `+0x38` field.
    //
    // Block above dumped `FREE_SHADOW` / `ALLOC_SHADOW` on `tls_phys`
    // — the page backing the TLS slot itself.  Block below resolves the
    // *value* of the TLS slot as a user VA (the heap-object pointer) and
    // dumps the same shadows on that page's phys, naming the most recent
    // free/alloc caller RIPs for the heap frame.  Per saga-discipline
    // Rule 1 (phys-provenance first), this completes the W215/W216
    // aliasing-class falsification surface for the sc=1171 fingerprint.
    //
    // Refs: Intel SDM Vol. 3A §4.6 (paging address translation);
    // POSIX `mmap(2)` (anonymous-mapping zero-fill); CWE-908
    // (Use of Uninitialized Resource).
    if let Some(v) = tls_val {
        if v != 0 {
            if let Some(heap_phys) = crate::mm::vmm::virt_to_phys_in(cr3, v) {
                crate::serial_println!(
                    "[D10/HEAP-OBJ-PROV] tls_val={:#018x} heap_phys={:#x}",
                    v, heap_phys,
                );
                crate::mm::w215_diag::dump_free_shadow_for_phys(heap_phys);
                crate::mm::w215_diag::dump_alloc_shadow_for_phys(heap_phys);
            } else {
                crate::serial_println!(
                    "[D10/HEAP-OBJ-PROV] tls_val={:#018x} heap_phys=? (unmapped under cr3={:#x})",
                    v, cr3,
                );
            }
        } else {
            crate::serial_println!(
                "[D10/HEAP-OBJ-PROV] tls_val=0 — no heap pointer to resolve",
            );
        }
    } else {
        crate::serial_println!(
            "[D10/HEAP-OBJ-PROV] tls_val=? (slot unreadable, see earlier dump)",
        );
    }

    crate::serial_println!("[D8/FAULT-DUMP] end pid={} tid={}", pid, tid);
}
