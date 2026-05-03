//! KeBugCheck — NT-inspired kernel bugcheck (BSOD equivalent).
//!
//! When the kernel detects a fatal, unrecoverable condition,
//! [`ke_bugcheck`] prints a structured crash report to serial, freezes
//! all other CPUs, and either exits QEMU (test-mode) or halts forever.
//!
//! # Fault-immunity contract
//!
//! The bugcheck banner is the only diagnostic the kernel produces when
//! the system is already in a fatal state.  If the printer itself can
//! fault — for example because the heap is corrupt, the global serial
//! mutex is held by another CPU, or a `core::fmt::Display` impl
//! transitively allocates — the original cause is lost behind a
//! synthetic "fault while formatting" trace.  This module therefore
//! abides by a strict fault-immunity contract:
//!
//! 1. **No allocation.**  No `String`, `Vec`, `Box`, `format!`, or
//!    transitive `alloc::*` calls on the printer path.  All formatting
//!    goes through stack-resident `[u8; N]` buffers via
//!    [`crate::util::no_alloc_fmt::ArrayWriter`].
//! 2. **No sleeping locks.**  The printer never takes the
//!    `drivers::serial::SERIAL` mutex; it talks directly to COM1 via
//!    [`crate::util::no_alloc_fmt::bugcheck_serial_write_bytes`].
//! 3. **No `Display::fmt` for non-`&'static str` types.**  Numeric
//!    fields go through hand-rolled hex / decimal helpers; only
//!    `&'static str` (which lives in `.rodata`) is emitted directly.
//! 4. **No process-table lookups.**  The PID is read via the
//!    per-CPU lockless cache [`crate::proc::current_pid_lockless`];
//!    the THREAD_TABLE-walking [`crate::proc::current_pid`] is
//!    forbidden here because it could deadlock against a lock held
//!    on another CPU.
//! 5. **Re-entrancy guard.**  A second entry to [`ke_bugcheck`] from
//!    the same or another CPU emits one minimal "RE-ENTERED BUGCHECK"
//!    line via the lowest-level serial path and halts immediately —
//!    we never spin in a fault loop.
//!
//! # Snapshot semantics
//!
//! The five `code` / `p1`–`p4` parameters are `u64` by value, so the
//! caller's structures (which may themselves be corrupt) are already
//! copied before the printer runs.  Registers we capture *inside* the
//! printer (RBX, RBP, R12–R15, CR2, CR3, RFLAGS) come from inline asm
//! / control-register reads — no memory dereference, no allocation.
//!
//! # References
//! * Intel SDM Vol. 3 §6 (Interrupt and Exception Handling)
//! * OSDev Wiki, "Exceptions" — <https://wiki.osdev.org/Exceptions>

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::util::no_alloc_fmt::{
    ArrayWriter, bugcheck_serial_write_byte, bugcheck_serial_write_bytes,
    bugcheck_serial_write_str,
};

// ── Bugcheck codes ───────────────────────────────────────────────────────────
// NT-compatible codes where possible; AstryxOS-specific codes use 0xDEAD_xxxx.

/// NT: IRQL_NOT_LESS_OR_EQUAL
pub const BUGCHECK_IRQL_NOT_LESS: u32 = 0x0000_000A;
/// NT: KERNEL_STACK_INPAGE_ERROR
pub const BUGCHECK_KERNEL_STACK_INPAGE: u32 = 0x0000_0077;
/// NT: UNEXPECTED_KERNEL_MODE_TRAP
pub const BUGCHECK_UNEXPECTED_TRAP: u32 = 0x0000_007F;

/// AstryxOS: stack canary (STACK_END_MAGIC) corrupted
pub const BUGCHECK_CANARY_CORRUPT: u32 = 0xDEAD_0001;
/// AstryxOS: non-higher-half value passed to set_kernel_rsp / update_tss_rsp0
pub const BUGCHECK_BAD_KERNEL_RSP: u32 = 0xDEAD_0002;
/// AstryxOS: double fault
pub const BUGCHECK_DOUBLE_FAULT: u32 = 0xDEAD_0003;
/// AstryxOS: scheduler watchdog timer expired (no context switch for >10s)
pub const BUGCHECK_SCHEDULER_DEADLOCK: u32 = 0xDEAD_0004;
/// AstryxOS: PMM free list corruption
pub const BUGCHECK_PMM_CORRUPT: u32 = 0xDEAD_0005;
/// AstryxOS: triggered manually via debugger
pub const BUGCHECK_MANUAL_CRASH: u32 = 0xDEAD_0000;
/// AstryxOS: kernel-mode page fault (unhandled)
pub const BUGCHECK_KERNEL_PAGE_FAULT: u32 = 0xDEAD_0006;
/// AstryxOS: general protection fault in kernel mode
pub const BUGCHECK_KERNEL_GPF: u32 = 0xDEAD_0007;

/// Human-readable bug-check name, returned as a `&'static str` from a
/// match against rodata literals.  This MUST NOT allocate — the
/// fault-immunity contract is the whole reason this helper exists.
pub fn bugcheck_name(code: u32) -> &'static str {
    match code {
        BUGCHECK_IRQL_NOT_LESS       => "IRQL_NOT_LESS_OR_EQUAL",
        BUGCHECK_KERNEL_STACK_INPAGE => "KERNEL_STACK_INPAGE_ERROR",
        BUGCHECK_UNEXPECTED_TRAP     => "UNEXPECTED_KERNEL_MODE_TRAP",
        BUGCHECK_CANARY_CORRUPT      => "STACK_CANARY_CORRUPT",
        BUGCHECK_BAD_KERNEL_RSP      => "BAD_KERNEL_RSP",
        BUGCHECK_DOUBLE_FAULT        => "DOUBLE_FAULT",
        BUGCHECK_SCHEDULER_DEADLOCK  => "SCHEDULER_DEADLOCK",
        BUGCHECK_PMM_CORRUPT         => "PMM_CORRUPT",
        BUGCHECK_MANUAL_CRASH        => "MANUAL_CRASH",
        BUGCHECK_KERNEL_PAGE_FAULT   => "KERNEL_PAGE_FAULT",
        BUGCHECK_KERNEL_GPF          => "KERNEL_GPF",
        _                            => "UNKNOWN_BUGCHECK",
    }
}

// ── SMP coordination ─────────────────────────────────────────────────────────

/// Only ONE CPU handles the bugcheck.  Others halt immediately.
/// NT uses `KeBugCheckCount` (interlocked decrement); we use a simple CAS.
static BUGCHECK_OWNER: AtomicBool = AtomicBool::new(false);

/// Recursion-depth counter, kept for backwards compatibility with
/// callers that read it.  Non-zero means a bugcheck is in progress.
static BUGCHECK_RECURSIVE: AtomicU32 = AtomicU32::new(0);

/// Last-ditch re-entrancy guard.  Set the first time the bugcheck
/// printer runs; if it fires again (because the printer itself
/// faulted), we emit one minimal banner and halt without doing any
/// more formatting.
static BUGCHECK_REENTRY: AtomicBool = AtomicBool::new(false);

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Dump a single fixed-width hex line: `"  RIP:    0xHHHHHHHHHHHHHHHH\n"`
/// where the label has been padded to a fixed visual column so the
/// register dump aligns.
///
/// `label_padded` MUST be a `&'static str` (rodata) of fixed width.
#[inline(never)]
fn emit_reg_line(label_padded: &'static str, value: u64) {
    let mut buf = [0u8; 96];
    let mut w = ArrayWriter::new(&mut buf);
    w.push_str("  ");
    w.push_str(label_padded);
    w.push_hex_u64(value);
    w.push_byte(b'\n');
    bugcheck_serial_write_bytes(w.as_bytes());
}

/// Dump three hex values on one line — used for the GPR table.
#[inline(never)]
fn emit_three_hex(a_label: &'static str, a: u64,
                  b_label: &'static str, b: u64,
                  c_label: &'static str, c: u64) {
    let mut buf = [0u8; 192];
    let mut w = ArrayWriter::new(&mut buf);
    w.push_str("  ");
    w.push_str(a_label); w.push_hex_u64(a);
    w.push_str("  ");
    w.push_str(b_label); w.push_hex_u64(b);
    w.push_str("  ");
    w.push_str(c_label); w.push_hex_u64(c);
    w.push_byte(b'\n');
    bugcheck_serial_write_bytes(w.as_bytes());
}

/// Snapshot of the registers we can capture with no memory derefs.
///
/// RIP/RSP/CR2/error_code are passed in by the caller (they come from
/// the IRETQ frame and are already by-value `u64`).  The remaining
/// GPRs and control regs we read here, on the printer's own stack.
#[derive(Default)]
struct PrinterSnapshot {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp_local: u64,
    r8:  u64, r9:  u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
    cr2: u64, cr3: u64, cr4: u64,
    rflags: u64,
}

/// Read all 16 GPRs and the relevant control registers without
/// allocating or dereferencing anything.  Inline-asm reads only —
/// fault-free even with a corrupt heap or page tables.
///
/// We capture in small batches: a single asm! block that pulls 16
/// values at once exhausts the register allocator (Rust requires each
/// `out(reg)` to land in a distinct GPR, and there are exactly 16,
/// leaving none free for scratch).  Splitting also lets the compiler
/// spill safely between batches.
#[inline(always)]
unsafe fn capture_snapshot() -> PrinterSnapshot {
    let mut s = PrinterSnapshot::default();

    // Batch 1: callee-saved + RBP/RSP.  These are the most informative
    // for a stack walk and least likely to have been clobbered between
    // the original fault and our entry to ke_bugcheck.
    core::arch::asm!(
        "mov {rbx}, rbx",
        "mov {rbp}, rbp",
        "mov {rsp_local}, rsp",
        "mov {r12}, r12",
        "mov {r13}, r13",
        rbx = out(reg) s.rbx,
        rbp = out(reg) s.rbp,
        rsp_local = out(reg) s.rsp_local,
        r12 = out(reg) s.r12,
        r13 = out(reg) s.r13,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {r14}, r14",
        "mov {r15}, r15",
        r14 = out(reg) s.r14,
        r15 = out(reg) s.r15,
        options(nomem, nostack, preserves_flags),
    );

    // Batch 2: caller-saved GPRs.  These have likely been clobbered by
    // the bugcheck call frame (rax holds the return value path, rcx/rdx
    // are scratch in the SysV ABI), but we record them for completeness.
    core::arch::asm!(
        "mov {rax}, rax",
        "mov {rcx}, rcx",
        "mov {rdx}, rdx",
        "mov {rsi}, rsi",
        "mov {rdi}, rdi",
        rax = out(reg) s.rax,
        rcx = out(reg) s.rcx,
        rdx = out(reg) s.rdx,
        rsi = out(reg) s.rsi,
        rdi = out(reg) s.rdi,
        options(nomem, nostack, preserves_flags),
    );
    core::arch::asm!(
        "mov {r8},  r8",
        "mov {r9},  r9",
        "mov {r10}, r10",
        "mov {r11}, r11",
        r8  = out(reg) s.r8,
        r9  = out(reg) s.r9,
        r10 = out(reg) s.r10,
        r11 = out(reg) s.r11,
        options(nomem, nostack, preserves_flags),
    );

    // Control + flags registers — each in its own block, no spilling
    // pressure.
    core::arch::asm!("mov {}, cr2", out(reg) s.cr2, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, cr3", out(reg) s.cr3, options(nomem, nostack, preserves_flags));
    core::arch::asm!("mov {}, cr4", out(reg) s.cr4, options(nomem, nostack, preserves_flags));
    core::arch::asm!("pushfq; pop {}", out(reg) s.rflags, options(nomem));
    s
}

// ── Main entry point ─────────────────────────────────────────────────────────

/// Kernel bugcheck — the AstryxOS equivalent of NT's KeBugCheckEx / BSOD.
///
/// Prints a structured crash report to serial, freezes other CPUs, then:
/// * test-mode: exits QEMU via isa-debug-exit (exit code 3 = failure)
/// * production: halts (`cli; hlt` loop)
///
/// This function never returns and is fault-immune: see the module
/// docs for the full contract.
///
/// # Parameters
/// * `code` — bugcheck code identifying the type of crash.
/// * `p1`–`p4` — context-specific values (varies per bugcheck code).
#[inline(never)]
pub fn ke_bugcheck(code: u32, p1: u64, p2: u64, p3: u64, p4: u64) -> ! {
    // ── Step 0: disable interrupts on this CPU FIRST ─────────────────
    // Before we touch anything else we want to be uninterruptible —
    // a timer ISR firing here would call into `serial_println!` and
    // blow our fault-immunity contract.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }

    // ── Step 1: re-entrancy guard ────────────────────────────────────
    // If we re-enter (because the printer itself faulted on a previous
    // attempt), emit ONE minimal line via the lowest-level serial path
    // and halt.  No formatting beyond a fixed `&'static str`, no
    // register dump — we are already in a fault loop and must NOT
    // touch any more code that could re-fault.
    if BUGCHECK_REENTRY.swap(true, Ordering::AcqRel) {
        bugcheck_serial_write_str(
            "\n*** AETHER KERNEL BUGCHECK *** RE-ENTERED BUGCHECK — halting CPU\n");
        loop { unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); } }
    }

    // ── Step 2: elect one CPU to handle (SMP safe) ───────────────────
    // After REENTRY is set we still need to pick a single owner: a
    // second CPU that legitimately bugchecks (i.e. concurrent failures
    // on different cores) shouldn't dump a banner over ours.
    let is_owner = BUGCHECK_OWNER.compare_exchange(
        false, true, Ordering::AcqRel, Ordering::Acquire
    ).is_ok();

    if !is_owner {
        // Another CPU is already handling a bugcheck.  Halt forever.
        // We've already swapped REENTRY=true on this CPU, but that's
        // a per-CPU concern only when the printer re-faults, so the
        // owner CPU's REENTRY check still works correctly because the
        // owner is the FIRST CPU to swap it.
        loop { unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); } }
    }

    // Bump legacy counter for any external code that reads it.
    BUGCHECK_RECURSIVE.fetch_add(1, Ordering::Relaxed);

    // ── Step 3: capture the printer's own register snapshot ──────────
    // SAFETY: capture_snapshot uses `nomem, nostack` inline asm and
    // does not dereference any pointers.  Always safe.
    let snap = unsafe { capture_snapshot() };

    // ── Step 4: identify CPU + thread (lockless paths only) ──────────
    // `cpu_index()` reads APIC ID via MSR — fault-free.
    // `current_tid()` and `current_pid_lockless()` read per-CPU atomics.
    // We deliberately do NOT call `current_pid()` because that walks
    // THREAD_TABLE under a spin::Mutex; if another CPU holds that lock
    // we'd deadlock.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid_lockless();

    // ── Step 5: print bugcheck banner ────────────────────────────────
    // Every line goes through the bypass serial sink.  No mutex, no
    // allocator.  Hex/decimal formatting is hand-rolled into stack
    // buffers (max ~256 B per line).
    bugcheck_serial_write_str("\n");
    bugcheck_serial_write_str(
        "================================================================================\n");
    bugcheck_serial_write_str("*** AETHER KERNEL BUGCHECK ***\n\n");

    // Header line: "  Code:   0xXXXXXXXX (NAME)\n"
    {
        let mut buf = [0u8; 128];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_str("  Code:   ");
        w.push_hex_u32(code);
        w.push_str(" (");
        w.push_str(bugcheck_name(code));
        w.push_str(")\n");
        bugcheck_serial_write_bytes(w.as_bytes());
    }
    emit_reg_line("P1:     ", p1);
    emit_reg_line("P2:     ", p2);
    emit_reg_line("P3:     ", p3);
    emit_reg_line("P4:     ", p4);
    bugcheck_serial_write_str("\n");

    // CPU/PID/TID line: "  CPU: N  TID: T  PID: P\n"
    {
        let mut buf = [0u8; 128];
        let mut w = ArrayWriter::new(&mut buf);
        w.push_str("  CPU:    ");
        w.push_dec_u64(cpu as u64);
        w.push_str("   TID: ");
        w.push_dec_u64(tid as u64);
        w.push_str("   PID: ");
        w.push_dec_u64(pid as u64);
        w.push_byte(b'\n');
        bugcheck_serial_write_bytes(w.as_bytes());
    }

    // Control / status registers.
    emit_reg_line("CR2:    ", snap.cr2);
    emit_reg_line("CR3:    ", snap.cr3);
    emit_reg_line("CR4:    ", snap.cr4);
    emit_reg_line("RFLAGS: ", snap.rflags);
    emit_reg_line("RSP-bp: ", snap.rsp_local); // RSP at printer entry (post-prologue)

    // ── Step 6: GPR dump (all 16, three per line) ────────────────────
    // Two-blank-line gutter, then a header, then the table.  Labels
    // are fixed-width `&'static str` so the columns line up.
    bugcheck_serial_write_str("\n  General-purpose registers:\n");
    emit_three_hex("rax=", snap.rax, "rbx=", snap.rbx, "rcx=", snap.rcx);
    emit_three_hex("rdx=", snap.rdx, "rsi=", snap.rsi, "rdi=", snap.rdi);
    emit_three_hex("rbp=", snap.rbp, "r8 =", snap.r8,  "r9 =", snap.r9);
    emit_three_hex("r10=", snap.r10, "r11=", snap.r11, "r12=", snap.r12);
    emit_three_hex("r13=", snap.r13, "r14=", snap.r14, "r15=", snap.r15);

    // ── Step 7: walk RBP chain for stack trace ───────────────────────
    // We bound the walk and validate every frame pointer before
    // touching memory.  RBP must be in higher-half kernel space and
    // 8-byte-aligned; otherwise we stop.  Each dereference goes
    // through `read_u64_volatile` so the optimiser cannot rewrite it
    // into something that could fault inside a `Display::fmt`.
    bugcheck_serial_write_str("\n  Stack trace (RBP chain):\n");
    {
        let mut rbp = snap.rbp;
        for i in 0..10u64 {
            if rbp == 0 || rbp < 0xFFFF_8000_0000_0000 || (rbp & 0x7) != 0 {
                break;
            }
            // SAFETY: rbp is a higher-half kernel virtual address that
            // has been validated for alignment.  In a fault-free
            // kernel, the saved RBP/RIP at [rbp]/[rbp+8] is valid.
            // If they aren't, we re-fault and the REENTRY guard
            // halts — strictly better than corrupting the trace.
            let ret_addr = unsafe {
                crate::util::no_alloc_fmt::read_u64_volatile((rbp + 8) as *const u64)
            };
            if ret_addr == 0 { break; }

            let mut buf = [0u8; 96];
            let mut w = ArrayWriter::new(&mut buf);
            w.push_str("    #");
            w.push_dec_u64(i);
            w.push_str(": ");
            w.push_hex_u64(ret_addr);
            w.push_byte(b'\n');
            bugcheck_serial_write_bytes(w.as_bytes());

            let next_rbp = unsafe {
                crate::util::no_alloc_fmt::read_u64_volatile(rbp as *const u64)
            };
            if next_rbp <= rbp {
                // Frame pointer must climb (rsp grows downward, the
                // saved RBP of the caller is higher than ours).  A
                // non-monotonic chain means the stack is corrupt; bail.
                break;
            }
            rbp = next_rbp;
        }
    }

    bugcheck_serial_write_str("\n");
    bugcheck_serial_write_str(
        "================================================================================\n");

    // ── Step 8: exit or halt ─────────────────────────────────────────
    #[cfg(feature = "test-mode")]
    {
        bugcheck_serial_write_str("[BUGCHECK] test-mode: exiting QEMU (code 3)\n");
        // SAFETY: writing to the QEMU isa-debug-exit port is the
        // standard test-harness escape hatch.  Value `1` produces
        // exit code (1*2)+1 = 3 (failure).  If the device is absent,
        // the write is a no-op and we fall through to the halt loop.
        unsafe { crate::hal::outl(0xF4, 1); }
    }

    // Production or if debug-exit didn't work: halt forever.
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
    }
}

/// Check if a bugcheck is in progress (used by timer ISR to halt
/// instead of continuing).
#[inline]
pub fn is_bugcheck_active() -> bool {
    BUGCHECK_OWNER.load(Ordering::Acquire)
}
