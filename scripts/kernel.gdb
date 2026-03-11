# AstryxOS Kernel GDB Init Script
#
# Usage:  gdb -x scripts/kernel.gdb
#
# The kernel ELF links at physical 0x100000 but runs at virtual
# 0xFFFF800000100000 (KERNEL_VIRT_BASE = 0xFFFF800000000000).
# We load symbols with that offset so breakpoints match runtime addresses.

set architecture i386:x86-64
set disassembly-flavor intel
set pagination off
set print pretty on
set print array on
set print array-indexes on

# ── Symbol loading ─────────────────────────────────────────────────────────────
# The kernel is linked at physical 0x100000 and runs there (no higher-half remap).
# KERNEL_VIRT_BASE (0xFFFF800000000000) is just a constant used for address
# range checks — the CPU never executes at those addresses.

file target/x86_64-astryx/release/astryx-kernel

# ── Connect to QEMU ────────────────────────────────────────────────────────────
target remote :1234

echo \n[GDB] Connected to QEMU. Kernel symbols loaded at physical base 0x100000\n

# ── Convenience functions ──────────────────────────────────────────────────────

# Break when schedule() is entered — useful for tracing scheduler decisions.
# Enable/disable with:  enable/disable 1
define hook-break-schedule
    break astryx_kernel::sched::schedule
end

# Break when a thread is about to be context-switched in.
# This fires for every switch_context_asm call.
define hook-break-switchctx
    break switch_context_asm
end

# Break when user_mode_bootstrap is called for a new process.
define hook-break-bootstrap
    break astryx_kernel::proc::usermode::user_mode_bootstrap
end

# Print the current CPU's RIP, RSP, RBP, and general purpose registers.
define cpu-state
    printf "=== CPU State ===\n"
    info registers rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15
end
document cpu-state
Print key CPU registers.
end

# Decode RSP: show what's on the top of the stack (return address chain).
define stack-top
    printf "=== Stack (top 16 words) ===\n"
    x/16gx $rsp
end
document stack-top
Show top 16 quad-words of the current stack.
end

# Read a byte from a physical address using QEMU's monitor memory access.
# For virtual addresses just use:  x/gx 0xFFFF800000XXXXXX
define virt-read
    x/gx $arg0
end
document virt-read
Read 8 bytes at a virtual address.  Usage: virt-read 0xFFFF800000XXXXXX
end

# Backtrace with mixed source/asm (useful for no_std kernels).
define kbt
    bt 20
end
document kbt
Print a 20-frame backtrace.
end

# ── TCC debugging breakpoints ──────────────────────────────────────────────────
# Uncomment the block you want before typing 'continue'.
#
# Option A: break the moment schedule() runs on any CPU.
#   This is very noisy (fires on every scheduler tick).
#   Better to use a conditional or 'tbreak' (temporary breakpoint).
#
#   tbreak astryx_kernel::sched::schedule
#
# Option B: break only in switch_context_asm.
#   Check rdi (old_rsp_ptr), rsi (new_rsp), rdx (new_cr3).
#   If rsi is invalid (e.g. NULL/garbage) that's the root cause.
#
#   break switch_context_asm
#
# Option C: break on user_mode_bootstrap — fires once per new process.
#   If TID 13 (TCC) never triggers this, it was never context-switched in.
#
#   break astryx_kernel::proc::usermode::user_mode_bootstrap
#
# ── Useful one-liners once stopped ────────────────────────────────────────────
#
#   info threads                      — GDB thread list (one per QEMU vCPU)
#   thread 1                          — switch to vCPU 1
#   thread 2                          — switch to vCPU 2
#   bt                                — backtrace for current vCPU
#   p/x $rip                          — current instruction pointer
#   p/x $rsp                          — current stack pointer
#   x/10i $rip                        — disassemble 10 instructions at rip
#
# ── After connecting, recommended first steps: ────────────────────────────────
#
#   (gdb) break astryx_kernel::proc::usermode::user_mode_bootstrap
#   (gdb) break switch_context_asm
#   (gdb) continue
#   -- wait until serial log shows "Waiting for TCC..." --
#   -- if bootstrap breakpoint never fires for TID 13, switch_context is broken --
#   -- at switch_context_asm: check rsi (new RSP) is a valid kernel stack addr --

echo \n[GDB] Ready. Useful commands: cpu-state, stack-top, kbt\n
echo [GDB] Suggested breakpoints:\n
echo   break astryx_kernel::proc::usermode::user_mode_bootstrap\n
echo   break switch_context_asm\n
echo   continue\n\n
