# Syscall/Linux-ABI Agent Status

**Role**: Adding missing Linux syscall stubs + ISR deadlock fix + testing

**Current state** (2026-03-12 — UPDATED):

## Completed Changes
- `mlock(149)/munlock(150)/mlockall(151)/munlockall(152)` → 0 (no-op stubs)
- `execveat(322)` → delegates to execve for non-empty paths, ENOSYS for fd-based
- `copy_file_range(326)` → delegates to sys_sendfile
- `Test 81` (test_new_syscall_stubs) added to test_runner.rs
- `scripts/run-test2.sh` — isolated test script (build/test2/ dir, no conflicts)

## ISR Deadlock Fix (CRITICAL BUG FIX)
**Root cause found**: When user process faults in Ring 3 with no handler, the page fault ISR
calls `exit_thread(-11)` → `schedule()`. But ISR runs with interrupts disabled. `schedule()`
context-switches to idle thread WITH interrupts still disabled. Idle thread runs `hlt` with
interrupts disabled → CPU hangs forever. This caused test 45 (Dynamic ELF) to hang.

**Fix applied** in `kernel/src/arch/x86_64/idt.rs`:
- Added `crate::hal::enable_interrupts()` BEFORE `exit_thread` calls in BOTH:
  - The page fault Ring 3 kill path (exception_handler, ~line 253)
  - The generic exception Ring 3 kill path (exception_handler, ~line 292)
- NOTE: These changes are in `exception_handler`, NOT in `handle_page_fault`
  (which the fork-cow agent is modifying — no conflict)

## Test Status
- Tests passing (exit code 0 confirmed from run-test2.sh)
- Test 45 (Dynamic ELF) now progresses past the previously hung point
- Full 81/81 count pending — current test2 QEMU still running

## Files Modified
- `kernel/src/syscall/mod.rs` — syscall stubs at dispatch_linux()
- `kernel/src/test_runner.rs` — test 81
- `kernel/src/arch/x86_64/idt.rs` — enable_interrupts() before exit_thread in exception_handler
- `scripts/run-test2.sh` — NEW isolated test script

## Files I DON'T Touch (fork-cow agent owns these)
- `kernel/src/mm/vma.rs` clone_for_fork function
- `kernel/src/proc/mod.rs` fork_process function
- `kernel/src/arch/x86_64/idt.rs` handle_page_fault function

## Active QEMU
- PID 123784 using build/test2/ (test-serial2.log)
- Do NOT use build/test2/ while this is running
