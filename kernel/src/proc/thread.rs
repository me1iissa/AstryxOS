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
);

extern "C" {
    /// Perform a context switch between two threads.
    ///
    /// Saves the current thread's callee-saved registers on its stack,
    /// stores its RSP to *old_rsp_ptr, then sets *ctx_valid_ptr = 1
    /// (if non-null) to atomically signal that the saved RSP is valid.
    /// Then loads new_rsp and resumes the new thread.
    ///
    /// # Safety
    /// Both pointers must be valid. `new_rsp` must point to a properly
    /// initialized stack (either from a previous switch_context, or from
    /// `init_thread_stack`). `ctx_valid_ptr` must be null or point to a
    /// valid `u8` (the `ctx_rsp_valid` byte of the outgoing thread).
    pub fn switch_context_asm(old_rsp_ptr: *mut u64, new_rsp: u64, ctx_valid_ptr: *mut u8);
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
    unsafe {
        // Alignment padding (unused value)
        *top.sub(1) = 0;
        // Return address: thread_entry_trampoline
        *top.sub(2) = thread_entry_trampoline as *const () as u64;
        // rbp = 0
        *top.sub(3) = 0;
        // rbx = entry_point (the trampoline reads this)
        *top.sub(4) = entry_point;
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
