//! Thread entry trampoline and context switch primitives.
//!
//! The context switch uses a cooperative switching model:
//! 1. Save callee-saved registers (rbx, rbp, r12-r15) to current stack.
//! 2. Save RSP to old thread's context.
//! 3. Load RSP from new thread's context.
//! 4. Pop callee-saved registers from new stack.
//! 5. "Return" — which lands at whatever RIP was on the new thread's stack.
//!
//! For newly-created threads, the stack is pre-initialized so that the
//! first "return" from switch_context jumps into `thread_entry_trampoline`,
//! which then calls the actual entry point stored in RBX.
//!
//! **IMPORTANT**: `switch_context` is defined via `global_asm!` to guarantee
//! it is a real function (with no compiler prologue/epilogue). If it were
//! inline asm, the compiler could inline it into `schedule()`, causing the
//! `ret` to pop the wrong value from the stack (a compiler-pushed register
//! rather than the actual return address), resulting in an Invalid Opcode.

use core::arch::asm;

/// Trampoline for newly created threads.
///
/// When a new thread is first scheduled, switch_context "returns" into this
/// function. At that point, RBX contains the real entry point (set up by
/// create_kernel_process / create_thread).
///
/// After the entry point returns, we call exit_thread.
pub extern "C" fn thread_entry_trampoline() {
    // RBX was restored by switch_context and holds the real entry point.
    let entry: u64;
    unsafe {
        asm!("mov {}, rbx", out(reg) entry, options(nomem, nostack));
    }
    // Cast to function pointer and call it.
    let func: fn() = unsafe { core::mem::transmute(entry) };
    func();

    // If the entry point returns, exit the thread.
    super::exit_thread(0);
}

// ═══════════════════════════════════════════════════════════════════════
//  Context Switch — defined in pure assembly to prevent inlining.
//
//  Using global_asm! guarantees no compiler prologue/epilogue.
//  The function follows the System V AMD64 ABI:
//    RDI = old_rsp_ptr (*mut u64 — where to save the old thread's RSP)
//    RSI = new_rsp     (the new thread's saved RSP)
// ═══════════════════════════════════════════════════════════════════════
core::arch::global_asm!(
    ".global switch_context_asm",
    ".type switch_context_asm, @function",
    "switch_context_asm:",
    // Args: RDI = old_rsp_ptr, RSI = new_rsp, RDX = ctx_valid_ptr (u8*, may be NULL)
    // Save callee-saved registers onto current stack
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // Save current RSP to *old_rsp_ptr
    "mov [rdi], rsp",
    // Atomically signal that the saved RSP is now valid.
    // RDX points to the thread's ctx_rsp_valid byte (AtomicBool).
    // Writing '1' here (BEFORE switching stacks) means: any CPU that reads
    // ctx_rsp_valid==1 is guaranteed to also see the updated RSP above.
    // x86 TSO ensures the store to [rdi] is visible before the store to [rdx]
    // from any other CPU's perspective once they observe the [rdx] store.
    "test rdx, rdx",
    "jz 1f",
    "mov byte ptr [rdx], 1",  // ctx_rsp_valid = true
    "1:",
    // Load new RSP
    "mov rsp, rsi",
    // Restore callee-saved registers from new stack
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    // "ret" pops the return address from the new stack and jumps there.
    // For an existing thread, this returns to after its own call to switch_context_asm.
    // For a new thread, this returns to thread_entry_trampoline.
    "ret",
    ".size switch_context_asm, . - switch_context_asm",

    // ── ret_from_fork_asm ────────────────────────────────────────────────
    // Fork child return-to-userspace trampoline (Linux ret_from_fork pattern).
    //
    // switch_context_asm's `ret` lands here for fork children.  At entry:
    //   r12-r15 = parent's callee-saved regs (restored by switch_context_asm pops)
    //   rbp     = parent's RBP (restored by switch_context_asm pop)
    //   RSP →   [tls_base, saved_rbx, SS, user_rsp, RFLAGS, CS, user_rip]
    //
    // This trampoline:
    //   1. Restores FS base (TLS) from the pre-built stack frame
    //   2. Restores RBX from parent
    //   3. Zeroes scratch registers (security: prevent kernel data leak)
    //   4. Executes IRETQ to enter Ring 3 with RAX=0 (fork child return)
    //
    // NO Rust function calls.  NO `call` instructions.  The IRETQ frame was
    // pre-built by init_fork_child_stack() at fork time.
    ".global ret_from_fork_asm",
    ".type ret_from_fork_asm, @function",
    "ret_from_fork_asm:",
    // Pop TLS base and write to FS_BASE MSR if non-zero
    "pop rax",                     // tls_base
    "test rax, rax",
    "jz 2f",
    "mov ecx, 0xC0000100",        // IA32_FS_BASE
    "mov rdx, rax",
    "shr rdx, 32",                // high 32 bits → EDX
    "mov eax, eax",               // low 32 bits (zero-extend) → EAX
    "wrmsr",
    "2:",
    // Pop parent's RBX
    "pop rbx",
    // Zero ALL scratch registers (prevent kernel address leak to Ring 3)
    "xor eax, eax",               // RAX = 0 (fork returns 0 in child)
    "xor ecx, ecx",
    "xor edx, edx",
    "xor esi, esi",
    "xor edi, edi",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    // RSP now points to the pre-built IRETQ frame: [SS, RSP, RFLAGS, CS, RIP]
    "iretq",
    ".size ret_from_fork_asm, . - ret_from_fork_asm",
);

extern "C" {
    /// Perform a context switch between two threads.
    pub fn switch_context_asm(old_rsp_ptr: *mut u64, new_rsp: u64, ctx_valid_ptr: *mut u8);
    /// Fork child return-to-userspace trampoline (address used by init_fork_child_stack).
    fn ret_from_fork_asm();
}

/// Safe-ish wrapper that calls the assembly context switch.
///
/// # Safety
/// Same requirements as `switch_context_asm`.
#[inline(never)]
pub unsafe fn switch_context(old_rsp_ptr: *mut u64, new_rsp: u64, ctx_valid_ptr: *mut u8) {
    switch_context_asm(old_rsp_ptr, new_rsp, ctx_valid_ptr);
}

/// Initialize a new thread's kernel stack so that the first switch_context
/// into it will "return" to `thread_entry_trampoline` with `entry_point` in RBX.
///
/// Returns the initial RSP to store in the thread's CpuContext.
///
/// Stack layout (growing downward, top = high address):
/// ```text
///   [stack_top - 8]   = 0                         (alignment padding — ensures
///                                                   RSP mod 16 == 8 on trampoline entry,
///                                                   as required by the System V ABI)
///   [stack_top - 16]  = thread_entry_trampoline   (return address for "ret")
///   [stack_top - 24]  = 0                         (rbp)
///   [stack_top - 32]  = entry_point               (rbx — used by trampoline)
///   [stack_top - 40]  = 0                         (r12)
///   [stack_top - 48]  = 0                         (r13)
///   [stack_top - 56]  = 0                         (r14)
///   [stack_top - 64]  = 0                         (r15)
///   ^ initial RSP
/// ```
///
/// After switch_context pops 6 registers (48 bytes) and does `ret` (+8 bytes),
/// RSP ends up at `stack_top - 8`, which is 16-byte aligned + 8 — correct for
/// the System V AMD64 ABI function entry convention.
pub fn init_thread_stack(stack_top: u64, entry_point: u64) -> u64 {
    let top = stack_top as *mut u64;

    // Fix truncated function pointers caused by mcmodel=kernel.
    //
    // With code-model "kernel", the Rust compiler assumes all code/data addresses
    // fit in a 32-bit sign-extended value (top 2 GB of the 64-bit address space).
    // Our kernel VMA (0xFFFF_8000_0010_0000) is NOT in the top 2 GB, so function
    // pointers are truncated to their physical (LMA) address.
    //
    // Fix: if a function pointer's bit 47 is clear (not in higher-half), add
    // KERNEL_VIRT_BASE to reconstruct the correct VMA.  This ensures switch_context's
    // `ret` instruction jumps to the higher-half address (PML4[256], mapped in all
    // page tables) rather than the identity-mapped physical address (PML4[0], which
    // is per-process user address space).
    let trampoline_addr = fixup_fn_ptr(thread_entry_trampoline as *const () as u64);
    let entry_addr = fixup_fn_ptr(entry_point);

    unsafe {
        // Alignment padding (unused value)
        *top.sub(1) = 0;
        // Return address: thread_entry_trampoline (higher-half VMA)
        *top.sub(2) = trampoline_addr;
        // rbp = 0
        *top.sub(3) = 0;
        // rbx = entry_point (the trampoline reads this, higher-half VMA)
        *top.sub(4) = entry_addr;
        // r12 = 0
        *top.sub(5) = 0;
        // r13 = 0
        *top.sub(6) = 0;
        // r14 = 0
        *top.sub(7) = 0;
        // r15 = 0
        *top.sub(8) = 0;
    }
    // Initial RSP points just below the last pushed register
    stack_top - 8 * 8
}

/// Fix a potentially truncated function pointer by adding KERNEL_VIRT_BASE.
///
/// With mcmodel=kernel, function pointers may be truncated to their physical
/// (LMA) address.  This function checks if bit 47 is clear (indicating a
/// truncated physical address) and adds KERNEL_VIRT_BASE to produce the
/// correct higher-half VMA.
///
/// For addresses that are already in the higher-half (bit 47 set), the
/// address is returned unchanged.
#[inline]
pub fn fixup_fn_ptr(addr: u64) -> u64 {
    if addr != 0 && (addr & (1u64 << 47)) == 0 {
        astryx_shared::KERNEL_VIRT_BASE + addr
    } else {
        addr
    }
}

/// Initialize a fork child's kernel stack with a pre-built IRETQ frame.
///
/// Unlike `init_thread_stack` (which uses `thread_entry_trampoline` → Rust function),
/// this builds the entire return-to-userspace frame at fork time.  When the scheduler
/// picks this child, `switch_context_asm` pops callee-saved regs and `ret` lands
/// directly in `ret_from_fork_asm` (pure assembly), which restores TLS, RBX, zeroes
/// scratch regs, and does IRETQ.  No Rust function calls in the path.
///
/// This is the Linux `copy_thread` + `ret_from_fork_asm` pattern.
///
/// Stack layout (growing downward, top = high address):
/// ```text
///   [stack_top - 8]   = 0                    (alignment padding)
///   [stack_top - 16]  = ret_from_fork_asm    (return address for switch_context ret)
///   [stack_top - 24]  = fork_regs.rbp        (rbp — popped by switch_context)
///   [stack_top - 32]  = 0                    (rbx — switch_context pops, ignored)
///   [stack_top - 40]  = fork_regs.r12        (r12 — popped by switch_context)
///   [stack_top - 48]  = fork_regs.r13        (r13 — popped by switch_context)
///   [stack_top - 56]  = fork_regs.r14        (r14 — popped by switch_context)
///   [stack_top - 64]  = fork_regs.r15        (r15 — popped by switch_context)
///   ── switch_context pops above, ret → ret_from_fork_asm ──
///   [stack_top - 72]  = tls_base             (popped by ret_from_fork_asm → WRMSR FS_BASE)
///   [stack_top - 80]  = fork_regs.rbx        (popped by ret_from_fork_asm → RBX)
///   [stack_top - 88]  = 0x1B                 (SS — USER_DATA_SELECTOR)
///   [stack_top - 96]  = user_rsp             (RSP — popped by IRETQ)
///   [stack_top - 104] = 0x202                (RFLAGS — IF set)
///   [stack_top - 112] = 0x23                 (CS — USER_CODE_SELECTOR)
///   [stack_top - 120] = user_rip             (RIP — popped by IRETQ)
///   ^ initial RSP
/// ```
pub fn init_fork_child_stack(
    stack_top: u64,
    user_rip: u64,
    user_rsp: u64,
    tls_base: u64,
    fork_regs: &super::ForkUserRegs,
) -> u64 {
    // Stack grows DOWN. switch_context_asm pops from initial_rsp UPWARD.
    // Layout (high address = top, low address = bottom):
    //
    //   stack_top - 8    = alignment padding
    //   stack_top - 16   = ret_from_fork_asm   ← popped by switch_context `ret`
    //   stack_top - 24   = rbp                  ← popped by switch_context `pop rbp`
    //   stack_top - 32   = 0 (rbx placeholder) ← popped by switch_context `pop rbx`
    //   stack_top - 40   = r12                  ← popped by switch_context `pop r12`
    //   stack_top - 48   = r13                  ← popped by switch_context `pop r13`
    //   stack_top - 56   = r14                  ← popped by switch_context `pop r14`
    //   stack_top - 64   = r15                  ← popped by switch_context `pop r15`
    //                                              (initial_rsp points here)
    //
    // After switch_context pops 6 regs (48 bytes) + ret (8 bytes),
    // RSP = initial_rsp + 56 = stack_top - 8.
    // ret pops from stack_top - 16 → RSP = stack_top - 8.
    //
    // Wait: pop r15 from initial_rsp, pop r14 from +8, pop r13 from +16,
    //       pop r12 from +24, pop rbx from +32, pop rbp from +40,
    //       ret pops from +48.
    //
    // So after switch_context: ret_addr is at initial_rsp + 48.
    // initial_rsp + 48 = (stack_top - 64) + 48 = stack_top - 16. Correct!
    //
    // After ret: RSP = stack_top - 8. But that's the alignment padding.
    // ret_from_fork_asm starts executing. RSP = stack_top - 8.
    // But we need ret_from_fork_asm to pop tls_base and rbx, then IRETQ.
    // So those must be at stack_top - 8 downward? NO — RSP = stack_top - 8
    // means the next pop reads from stack_top - 8. But that's the alignment
    // padding (value 0). That's wrong!
    //
    // Fix: put the ret_from_fork data ABOVE the alignment padding.
    // Better: rethink the layout. After ret, RSP points to stack_top - 8.
    // But ret consumed the word at stack_top - 16 (ret_from_fork_asm addr).
    // After ret, RSP = (stack_top - 16) + 8 = stack_top - 8.
    // A `pop` reads from RSP and increments. So first pop reads stack_top - 8.
    //
    // I need to put the ret_from_fork data at stack_top - 8 and above:
    //
    //   stack_top - 8    = tls_base             ← popped by ret_from_fork `pop rax`
    //   stack_top - 16   = rbx                  ← popped by ret_from_fork `pop rbx`
    //
    // Wait, pop reads from RSP (stack_top - 8) and RSP becomes stack_top.
    // Second pop reads from stack_top and RSP becomes stack_top + 8.
    // But stack_top + 8 is ABOVE the stack! That's a buffer overrun.
    //
    // The real issue: after ret, RSP goes UP. We need the ret_from_fork data
    // to be BETWEEN the ret address and the alignment padding. But there's
    // no room there.
    //
    // SOLUTION: Don't use alignment padding at the top. Instead:
    //
    //   stack_top - 8    = user_rip              ← IRETQ pops RIP
    //   stack_top - 16   = 0x23                  ← IRETQ pops CS
    //   stack_top - 24   = 0x202                 ← IRETQ pops RFLAGS
    //   stack_top - 32   = user_rsp              ← IRETQ pops RSP
    //   stack_top - 40   = 0x1B                  ← IRETQ pops SS
    //   stack_top - 48   = rbx_val               ← ret_from_fork pops RBX
    //   stack_top - 56   = tls_base              ← ret_from_fork pops RAX (TLS)
    //   stack_top - 64   = ret_from_fork_asm     ← switch_context `ret` pops this
    //   stack_top - 72   = rbp_val               ← switch_context `pop rbp`
    //   stack_top - 80   = 0                     ← switch_context `pop rbx` (ignored)
    //   stack_top - 88   = r12_val               ← switch_context `pop r12`
    //   stack_top - 96   = r13_val               ← switch_context `pop r13`
    //   stack_top - 104  = r14_val               ← switch_context `pop r14`
    //   stack_top - 112  = r15_val               ← switch_context `pop r15`
    //                                               (initial_rsp points here)
    //
    // switch_context pops r15..rbp (6 regs, 48 bytes), then ret (8 bytes).
    // After ret: RSP = initial_rsp + 56 = (stack_top-112) + 56 = stack_top - 56.
    // ret_from_fork_asm: pop rax → reads stack_top-56 (tls_base), RSP→stack_top-48
    //                    pop rbx → reads stack_top-48 (rbx_val), RSP→stack_top-40
    //                    iretq   → pops SS,RSP,RFLAGS,CS,RIP from stack_top-40..stack_top-8
    //
    // IRETQ order: [RSP+0]=RIP, [RSP+8]=CS, [RSP+16]=RFLAGS, [RSP+24]=RSP, [RSP+32]=SS
    // So RSP points to stack_top-40:
    //   [RSP+0]  = stack_top-40 = 0x1B (SS)  ← WRONG! IRETQ expects RIP first!
    //
    // IRETQ pops in order: RIP(RSP+0), CS(+8), RFLAGS(+16), RSP(+24), SS(+32)
    // So the frame needs: RIP at lowest address, SS at highest.
    //
    // Let me write: lowest addr → highest addr = RIP, CS, RFLAGS, RSP, SS
    //
    let top = stack_top as *mut u64;
    unsafe {
        // IRETQ frame (RIP at lowest address, SS at highest)
        *top.sub(1) = 0x1B;                                      // SS  (highest in frame)
        *top.sub(2) = user_rsp;                                  // RSP
        *top.sub(3) = 0x202;                                     // RFLAGS
        *top.sub(4) = 0x23;                                      // CS
        *top.sub(5) = user_rip;                                  // RIP (lowest in frame)

        // ret_from_fork_asm pops (after switch_context ret)
        *top.sub(6) = fork_regs.rbx;                             // popped by `pop rbx`
        *top.sub(7) = tls_base;                                  // popped by `pop rax` (TLS)

        // switch_context_asm frame (ret_addr at highest, r15 at lowest)
        *top.sub(8)  = ret_from_fork_asm as *const () as u64;    // `ret` pops this
        *top.sub(9)  = fork_regs.rbp;                            // `pop rbp`
        *top.sub(10) = 0;                                        // `pop rbx` (unused)
        *top.sub(11) = fork_regs.r12;                            // `pop r12`
        *top.sub(12) = fork_regs.r13;                            // `pop r13`
        *top.sub(13) = fork_regs.r14;                            // `pop r14`
        *top.sub(14) = fork_regs.r15;                            // `pop r15` (first pop)
    }
    // initial_rsp = bottom of switch_context frame
    stack_top - 14 * 8
}
