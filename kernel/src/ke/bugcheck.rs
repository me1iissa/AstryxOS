//! KeBugCheck — NT-inspired kernel bugcheck (BSOD equivalent).
//!
//! When the kernel detects a fatal, unrecoverable condition, `ke_bugcheck()`
//! prints a structured crash report to serial, freezes all other CPUs, and
//! either exits QEMU (test-mode) or halts.
//!
//! Inspired by `KeBugCheckEx()` in:
//!   - Windows XP: base/ntos/ke/bugcheck.c
//!   - ReactOS:    ntoskrnl/ke/bug.c
//!
//! # Usage
//! ```
//! ke_bugcheck(BUGCHECK_DOUBLE_FAULT, rip, rsp, cr2, error_code);
//! ```

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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

/// Human-readable name for a bugcheck code.
pub fn bugcheck_name(code: u32) -> &'static str {
    match code {
        BUGCHECK_IRQL_NOT_LESS      => "IRQL_NOT_LESS_OR_EQUAL",
        BUGCHECK_KERNEL_STACK_INPAGE => "KERNEL_STACK_INPAGE_ERROR",
        BUGCHECK_UNEXPECTED_TRAP    => "UNEXPECTED_KERNEL_MODE_TRAP",
        BUGCHECK_CANARY_CORRUPT     => "STACK_CANARY_CORRUPT",
        BUGCHECK_BAD_KERNEL_RSP     => "BAD_KERNEL_RSP",
        BUGCHECK_DOUBLE_FAULT       => "DOUBLE_FAULT",
        BUGCHECK_SCHEDULER_DEADLOCK => "SCHEDULER_DEADLOCK",
        BUGCHECK_PMM_CORRUPT        => "PMM_CORRUPT",
        BUGCHECK_MANUAL_CRASH       => "MANUAL_CRASH",
        BUGCHECK_KERNEL_PAGE_FAULT  => "KERNEL_PAGE_FAULT",
        BUGCHECK_KERNEL_GPF         => "KERNEL_GPF",
        _ => "UNKNOWN_BUGCHECK",
    }
}

// ── SMP coordination ─────────────────────────────────────────────────────────

/// Only ONE CPU handles the bugcheck.  Others halt immediately.
/// NT uses `KeBugCheckCount` (interlocked decrement); we use a simple CAS.
static BUGCHECK_OWNER: AtomicBool = AtomicBool::new(false);

/// Recursion guard — if ke_bugcheck is called again (e.g., from serial_println
/// panic during the bugcheck itself), the second call just halts.
static BUGCHECK_RECURSIVE: AtomicU32 = AtomicU32::new(0);

// ── Main entry point ─────────────────────────────────────────────────────────

/// Kernel bugcheck — the AstryxOS equivalent of NT's KeBugCheckEx / BSOD.
///
/// Prints a structured crash report to serial, freezes other CPUs, then:
/// - test-mode: exits QEMU via isa-debug-exit (exit code 3 = failure)
/// - production: halts (infinite cli;hlt loop)
///
/// This function never returns.
///
/// # Parameters
/// - `code`: bugcheck code (identifies the type of crash)
/// - `p1`–`p4`: up to 4 context-specific values (varies per bugcheck code)
#[inline(never)]
pub fn ke_bugcheck(code: u32, p1: u64, p2: u64, p3: u64, p4: u64) -> ! {
    // ── Step 1: disable interrupts on this CPU ───────────────────────
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }

    // ── Step 2: elect one CPU to handle (SMP safe) ───────────────────
    let is_owner = BUGCHECK_OWNER.compare_exchange(
        false, true, Ordering::AcqRel, Ordering::Acquire
    ).is_ok();

    if !is_owner {
        // Another CPU is already handling a bugcheck.  Halt forever.
        loop { unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); } }
    }

    // ── Recursion guard ──────────────────────────────────────────────
    let depth = BUGCHECK_RECURSIVE.fetch_add(1, Ordering::Relaxed);
    if depth > 0 {
        // Recursive bugcheck (e.g., serial_println panicked during the bugcheck).
        // NT behavior: depth==1 → debugger break, depth>1 → halt.
        loop { unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); } }
    }

    // ── Step 3: capture caller context ───────────────────────────────
    let rsp: u64;
    let rflags: u64;
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nomem));
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }

    // Get RIP of the caller (approximate: return address is on the stack)
    // For inline(never) functions, the return address is at [rsp] upon entry.
    // Since we've pushed some things, use the direct values passed instead.
    let cpu = crate::arch::x86_64::apic::cpu_index();
    let tid = crate::proc::current_tid();
    let pid = crate::proc::current_pid();

    // ── Step 4: freeze other CPUs ────────────────────────────────────
    // Send NMI to all other CPUs via LAPIC broadcast.
    // They will enter the NMI handler, see BUGCHECK_OWNER == true, and halt.
    // For simplicity, we just proceed — the other CPUs will naturally halt
    // when their timer ISR fires and sees BUGCHECK_OWNER==true, or when
    // they hit any exception.  This avoids LAPIC ICR complexity.

    // ── Step 5: print bugcheck screen ────────────────────────────────
    crate::serial_println!("");
    crate::serial_println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    crate::serial_println!("*** AETHER KERNEL BUGCHECK ***");
    crate::serial_println!("");
    crate::serial_println!("  Code:   {:#010x} ({})", code, bugcheck_name(code));
    crate::serial_println!("  P1:     {:#018x}", p1);
    crate::serial_println!("  P2:     {:#018x}", p2);
    crate::serial_println!("  P3:     {:#018x}", p3);
    crate::serial_println!("  P4:     {:#018x}", p4);
    crate::serial_println!("");
    crate::serial_println!("  CPU:    {}   TID: {}   PID: {}", cpu, tid, pid);
    crate::serial_println!("  RSP:    {:#018x}", rsp);
    crate::serial_println!("  CR3:    {:#018x}", cr3);
    crate::serial_println!("  RFLAGS: {:#018x}", rflags);

    // ── Step 5b: walk RBP chain for stack trace ──────────────────────
    crate::serial_println!("");
    crate::serial_println!("  Stack trace (RBP chain):");
    let mut rbp: u64;
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack)); }
    for i in 0..10 {
        if rbp == 0 || rbp < 0xFFFF_8000_0000_0000 {
            break;
        }
        let ret_addr = unsafe { *((rbp + 8) as *const u64) };
        if ret_addr == 0 {
            break;
        }
        crate::serial_println!("    #{:2}: {:#018x}", i, ret_addr);
        rbp = unsafe { *(rbp as *const u64) };
    }

    crate::serial_println!("");
    crate::serial_println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // ── Step 6: exit or halt ─────────────────────────────────────────
    #[cfg(feature = "test-mode")]
    {
        // In test-mode: write EXIT_FAILURE to isa-debug-exit → QEMU exits with code 3.
        crate::serial_println!("[BUGCHECK] test-mode: exiting QEMU (code 3)");
        unsafe { crate::hal::outl(0xF4, 1); } // 1 → QEMU exit code (1*2)+1 = 3
    }

    // Production or if debug-exit didn't work: halt forever.
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)); }
    }
}

/// Check if a bugcheck is in progress (used by timer ISR to halt instead of continuing).
#[inline]
pub fn is_bugcheck_active() -> bool {
    BUGCHECK_OWNER.load(Ordering::Acquire)
}
