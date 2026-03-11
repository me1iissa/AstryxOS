# GDB batch script — logs every switch_context_asm call and all user_mode_bootstrap calls.
# Run as: gdb --batch -x scripts/gdb-tcc-trace.gdb 2>&1 | tee build/gdb-trace.log

set architecture i386:x86-64
set disassembly-flavor intel
set pagination off
set logging file build/gdb-trace.log
set logging overwrite on
set logging enabled on

# Load symbols at physical addresses — the kernel runs at phys 0x100000+, no virt remap.
file target/x86_64-astryx/release/astryx-kernel

# Connect to QEMU
target remote :1234

echo \n=== GDB TCC Trace Session ===\n

# ── Breakpoint 1: switch_context_asm ─────────────────────────────────────────
# rdi = pointer to old thread's RSP storage
# rsi = new thread's RSP (what gets loaded into RSP)
# rdx = new CR3 (page table)
# Logs first 200 switches only to avoid flood.
set $switch_count = 0
break switch_context_asm
commands 1
  silent
  set $switch_count = $switch_count + 1
  if $switch_count <= 200
    printf "[SWITCH #%d] old_rsp_ptr=0x%lx new_rsp=0x%lx new_cr3=0x%lx\n", $switch_count, $rdi, $rsi, $rdx
  end
  if $switch_count == 200
    printf "[SWITCH] Suppressing further switch_context_asm logs (limit reached)\n"
  end
  continue
end

# ── Breakpoint 2: user_mode_bootstrap ────────────────────────────────────────
# This fires when a new user process thread is about to enter ring 3.
# EVERY invocation is logged — if TID 13 (TCC) never appears, it was never scheduled.
break astryx_kernel::proc::usermode::user_mode_bootstrap
commands 2
  printf "[BOOTSTRAP] user_mode_bootstrap called — CPU registers:\n"
  printf "  rip=0x%lx rsp=0x%lx rbp=0x%lx\n", $rip, $rsp, $rbp
  where 3
  continue
end

# ── Breakpoint 3: panic / abort ───────────────────────────────────────────────
# Catch any kernel panics during the TCC test.
break rust_begin_unwind
commands 3
  printf "[PANIC] rust_begin_unwind called!\n"
  where 10
  info registers
  continue
end

echo \n[GDB] Breakpoints set. Running kernel...\n
continue

# The kernel will run; GDB will log events and auto-continue.
# After a timeout QEMU exits and GDB exits with the batch.
