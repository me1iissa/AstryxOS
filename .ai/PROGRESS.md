# AstryxOS — Progress Tracker

## Current Phase: Core OS Infrastructure Complete (M8–M13) ✅
**Completed**: 2026-02-28
**Tests**: 27/27 passing

### Milestone 13 — Power Management ✅
**Completed**: 2026-02-28
- [x] Power state model (S0Working, S1Standby, S3Suspend, S4Hibernate, S5Shutdown)
- [x] Power action requests (Shutdown, Reboot, Sleep, Hibernate)
- [x] Power callback registry with priority-ordered notification
- [x] Shutdown sequence: phased (NotifyCallbacks → FlushCaches → StopDrivers → PowerOff)
- [x] flush_all_caches() integration with VFS sync_all
- [x] ACPI shutdown (q35 PM1a_CNT port 0x604, S5 transition)
- [x] System reboot (keyboard controller 0xFE + triple fault fallback)
- [x] Emergency shutdown (skip cleanup, immediate power off)
- [x] Atomic shutdown/reboot flags
- [x] Test 27: Power management (state, callbacks, phases, flush)
- [x] 27/27 tests passing

### Milestone 12 — I/O Completion Ports ✅
**Completed**: 2026-02-28
- [x] IoCompletionPort with FIFO packet queue and concurrency tracking
- [x] IoCompletionPacket (key, status, information, overlapped context)
- [x] IoStatus enum (Success, Pending, Error, Cancelled, EndOfFile, etc.)
- [x] Handle association: bind file handles to ports with completion keys
- [x] post_completion / dequeue_completion with spin-yield timeout
- [x] Global port registry (create, close, associate, stats)
- [x] AsyncIoRequest tracker (submit, complete, cancel async ops)
- [x] Auto-post to IOCP on async completion
- [x] Cancellation with automatic Cancelled packet posting
- [x] Multi-port isolation
- [x] Test 26: I/O completion ports (FIFO, association, timeout, async lifecycle, cancel, multi-port)
- [x] 26/26 tests passing

### Milestone 11 — Access Tokens + SIDs + Privileges ✅
**Completed**: 2026-02-28
- [x] Sid struct with revision, authority, sub_authorities
- [x] 11 well-known SIDs (Null, World, LocalSystem, LocalService, NetworkService, Admins, Users, etc.)
- [x] S-R-I-S-... string representation (Display impl)
- [x] Privilege enum (23 NT privileges: SeTcb, SeDebug, SeShutdown, SeBackup, etc.)
- [x] TokenPrivilege with enabled/enabled_by_default attributes
- [x] all_admin_privileges() and default_user_privileges()
- [x] AccessToken: user SID, groups, privileges, primary group, default DACL, source, session
- [x] TokenType (Primary/Impersonation) with ImpersonationLevel
- [x] TokenGroup with enabled, mandatory, owner, deny_only attributes
- [x] token_has_privilege, token_enable/disable_privilege
- [x] token_check_membership (user + enabled groups)
- [x] duplicate_token with type/level change
- [x] Global token registry (create_system_token, create_user_token, with_token, destroy)
- [x] check_token_access: bridges tokens to ACL-based SecurityDescriptor
- [x] Process.token_id field, assign_token helper, fork inherits token
- [x] Test 25: Security tokens/SIDs (SIDs, privileges, tokens, registry, access check)
- [x] 25/25 tests passing

### Milestone 10 — Executive Resources + Worker Threads ✅
**Completed**: 2026-02-28
- [x] EResource reader-writer lock (shared/exclusive, recursion, contention counting)
- [x] acquire_shared/acquire_exclusive with wait parameter
- [x] FastMutex: lightweight mutex with IRQL raise to APC level
- [x] try_acquire_fast_mutex for non-blocking
- [x] PushLock: slim reader-writer (Free/SharedRead(n)/Exclusive states)
- [x] System work queues: 3 priority tiers (HyperCritical/Critical/Delayed)
- [x] WorkItem with routine + context, priority-ordered processing
- [x] ex_queue_work_item convenience function
- [x] process_work_items: HyperCritical → Critical → Delayed order
- [x] Work queue stats (pending counts, total processed)
- [x] Test 24: Executive resources + work queues (all 4 subsystems + priority ordering)
- [x] 24/24 tests passing

### Milestone 9 — Dispatcher Objects + Wait Infrastructure ✅
**Completed**: 2026-02-28
- [x] DispatcherHeader with object_type, signal_state, wait_list
- [x] DispatcherObjectType (Event, Mutant, Semaphore, Timer)
- [x] WaitBlock with thread_id, WaitType (WaitAll/WaitAny), wait_key
- [x] KeEvent: NotificationEvent (manual-reset) + SynchronizationEvent (auto-reset)
- [x] set_event, reset_event, pulse_event, read_state_event
- [x] KeMutant: recursive mutex with owner tracking, abandoned detection
- [x] acquire_mutant, release_mutant with recursion count
- [x] KeSemaphore: counting semaphore with limit enforcement
- [x] release_semaphore with overflow protection
- [x] KeTimer: one-shot and periodic, DPC callback integration
- [x] Global timer registry with set_timer, cancel_timer, check_timers
- [x] Global dispatcher object registry with create_*/destroy_object
- [x] wait_for_single_object with timeout (spin-yield)
- [x] wait_for_multiple_objects: WaitAll + WaitAny with index tracking
- [x] WaitStatus: Satisfied(index), Timeout, Abandoned, Failed
- [x] Test 23: Dispatcher objects + wait (events, mutants, semaphores, timers, WaitAll, WaitAny)
- [x] 23/23 tests passing

### Milestone 8 — IRQL + DPC + APC Framework ✅
**Completed**: 2026-02-28
- [x] Irql enum: Passive(0), Apc(1), Dispatch(2), Device(3), High(4)
- [x] Per-CPU IRQL via AtomicU8, raise_irql/lower_irql/current_irql
- [x] cli/sti hardware interrupt control at Dispatch+ levels
- [x] DPC framework: DpcRoutine, DpcImportance (Low/Medium/High)
- [x] Global DPC queue (VecDeque), importance-based insertion (High=front)
- [x] drain_dpc_queue: processes all pending DPCs at Dispatch level
- [x] APC framework: per-thread BTreeMap queues (kernel + user mode)
- [x] ApcMode (Kernel/User), KernelApcRoutine
- [x] queue_apc, deliver_apcs, drain_kernel_apcs
- [x] Test 22: Ke IRQL/DPC/APC (raise/lower, DPC drain, APC deliver)
- [x] 22/22 tests passing

### Milestone 7 — Full NT Executive ✅
**Completed**: 2026-02-28

**Part A — NT Executive Core:**
- [x] KernelObject trait with object_type() and object_name()
- [x] ObjectHeader enhanced: security_descriptor, link_target, Box<dyn KernelObject> body
- [x] OB API: insert_with_sd, lookup_object_type, has_object, resolve_symlink, get_object_security_descriptor, remove_object
- [x] Handle Table (ob/handle.rs): per-process HandleTable with NT-style handles (multiples of 4)
- [x] HandleEntry: object_path, object_type, granted_access, inheritable
- [x] Handle ops: allocate, lookup, close, duplicate, count
- [x] handle_table field on Process (Some for kernel/user processes, None for idle)
- [x] IRP model: Irp struct, IrpMajorFunction enum (9 variants), IrpParameters
- [x] DriverObject with dispatch_table[9], DeviceObject with DeviceType
- [x] IoManager: register_driver, register_device, io_call_driver, io_create_file
- [x] Built-in drivers: NullDriver, ConsoleDriver, SerialDriver, E1000Driver
- [x] Security integration: check_object_access() bridges OB+Security, SD on objects
- [x] Test 20: NT Executive Core (OB+Handle+IoMgr+Security, 23 checks)

**Part B — ALPC + Win32 Subsystem:**
- [x] ALPC: AlpcMessage with msg_id, AlpcMessageType (Request/Reply/Datagram/ConnectionRequest/ConnectionReply)
- [x] ALPC server flow: connect_request, listen_port, accept_connection (accept/reject)
- [x] ALPC request/reply: send_request, wait_reply, send_reply with msg_id correlation
- [x] ALPC datagram: send_datagram (one-way, no reply)
- [x] ALPC port security: create_port_with_security, SecurityDescriptor on ports
- [x] ALPC views: AlpcView struct for shared memory (attach_view, get_view)
- [x] ALPC OB integration: ports auto-registered in Object Manager namespace
- [x] Legacy LPC backward compatibility preserved
- [x] Win32 subsystem (win32/mod.rs): SubsystemType enum (Native/Posix/Win32)
- [x] Win32Environment: desktop, window_station, console_handle, process_heap
- [x] Win32 init: WinSta0, Default desktop, CsrApiPort in OB
- [x] CsrApiNumber enum for CSRSS communication
- [x] Subsystem registry with registration/query
- [x] Process subsystem field (SubsystemType on every Process)
- [x] Test 21: ALPC + Win32 Subsystem (13 sections, A–M)
- [x] 21/21 tests passing

### Milestone 6 — Buffer Cache + File-backed mmap ✅
**Completed**: 2026-02-28
- [x] Global page cache (mm/cache.rs): BTreeMap keyed by (mount_idx, inode, page_offset)
- [x] PageCacheEntry with phys + dirty tracking
- [x] Cache ops: lookup, insert, evict, mark_dirty, sync_inode, stats
- [x] Automatic refcount management (inc on insert, dec on evict)
- [x] sys_mmap: accepts fd param, creates VmBacking::File VMAs for file-backed mappings
- [x] sys_munmap: decrements refcount per page, frees when refcount reaches 0
- [x] Page fault handler: VmBacking::File demand-loads from VFS via page cache
- [x] Cache coherency: same physical page shared across multiple mappings
- [x] Test 19: Buffer cache + file-backed mmap
- [x] 19/19 tests passing
- [x] SignalFrame struct (112 bytes, 14 fields: restorer, signum, mask, all GPRs)
- [x] Trampoline page at 0x7FFF_FFFF_F000 with AstryxOS (mov rax,39;syscall) + Linux (mov rax,15;syscall) sigreturn stubs
- [x] init_trampoline() allocates physical frame, writes machine code
- [x] map_trampoline(cr3) maps trampoline into user page tables (called in create_user_process + fork_process)
- [x] signal_check_on_syscall_return() called from syscall_entry asm after dispatch
- [x] Builds signal frame on user stack, redirects RIP to handler, sets RDI=signum
- [x] sys_sigreturn reads signal frame from user stack, restores all registers to kernel stack frame
- [x] rt_sigaction parses sa_flags/SA_RESTORER/sa_restorer from 32-byte Linux struct
- [x] SigAction::Handler extended with restorer field
- [x] Signal blocked during handler execution, restored by sigreturn
- [x] Test 18: Signal delivery trampoline
- [x] 18/18 tests passing

### Milestone 4 — musl-libc Stubs ✅
**Completed**: 2026-02-28
- [x] linux_abi flag on Process for Linux syscall number routing
- [x] dispatch_linux() with 40+ Linux x86_64 syscall number mappings
- [x] arch_prctl (SET_FS via WRMSR to FS_BASE MSR 0xC0000100)
- [x] set_tid_address, clock_gettime, mprotect (stub), writev
- [x] fcntl, access, gettimeofday, getdents64, openat, newfstatat
- [x] rt_sigaction, rt_sigprocmask (Linux ABI wrappers)
- [x] fill_linux_stat() — 144-byte Linux stat ABI
- [x] sigaltstack, exit_group stubs
- [x] Updated libsys with full syscall wrapper set
- [x] Test 17: Linux syscall compatibility
- [x] 17/17 tests passing

### Milestone 3 — FAT32 Write Support ✅
**Completed**: 2026-02-28
- [x] write_sectors() added to BlockDevice trait + AhciBlockDevice
- [x] Sparse BTreeMap<u64, [u8; 512]> sector cache with dirty tracking
- [x] FAT manipulation: alloc_cluster, extend_chain, free_chain
- [x] Directory write operations: create, write, remove, truncate
- [x] mkdir/rmdir support
- [x] sync() method on FileSystemOps, sync_all() public function
- [x] SYS_SYNC (49) syscall for explicit flush
- [x] Test 16: FAT32 write support
- [x] 16/16 tests passing

### Milestone 2 — TTY/termios Layer ✅
**Completed**: 2026-02-28
- [x] drivers/tty.rs: Tty struct with Termios, line discipline (canonical + raw)
- [x] TTY0 global Mutex<Tty>
- [x] process_input(), read(), write(), pump_keyboard()
- [x] tty_ioctl: TCGETS/TCSETS/TCSETSW/TCSETSF/TIOCGWINSZ
- [x] Extended VT100: CSI P/@/L/M/s/u/?25h/?25l/r (delete/insert chars/lines, cursor save/restore, scroll region)
- [x] SYS_READ fd 0 routed through TTY
- [x] SYS_WRITE fd 1/2 routed through TTY
- [x] Test 15: TTY subsystem
- [x] 15/15 tests passing

### Milestone 1 — Per-process Page Tables + CoW Fork + Exec ✅
**Completed**: 2026-02-28
- [x] refcount::init() called at boot (mm/mod.rs)
- [x] Per-process VmSpace with unique CR3 (VmSpace::new_user())
- [x] CR3 switching in scheduler on context switch (sched/mod.rs)
- [x] ELF loader uses map_page_in(cr3) instead of current CR3 (proc/elf.rs)
- [x] ELF loader creates VMAs for loaded segments + user stack
- [x] create_user_process() allocates per-process page tables (proc/usermode.rs)
- [x] fork_process() calls VmSpace::clone_for_fork() for real CoW (proc/mod.rs)
- [x] CoW page fault handler functional (demand paging + copy-on-write)
- [x] sys_exec() replaces process image with new VmSpace (syscall/mod.rs)
- [x] Test 14 updated: verifies per-process CR3, CoW fork, VmSpace population
- [x] 14/14 tests passing

### Phase 0 — Foundation & Tooling ✅
- [x] Project structure created (30+ source files)
- [x] AI guidelines and plan written
- [x] Cargo workspace setup (bootloader, kernel, shared crates)
- [x] Rust nightly toolchain + targets configured
- [x] UEFI bootloader (AstryxBoot) — compiles and runs
- [x] QEMU + OVMF test environment verified
- [x] Build system (build.sh) — generates FAT32 image + ISO
- [x] Bootloader loads kernel from ESP, exits boot services, jumps to kernel

### Phase 1 — Kernel Core ✅
- [x] GDT with TSS (kernel/user segments, interrupt + double-fault stacks)
- [x] IDT with 256 vectors (exceptions 0–19, IRQ 32–33, syscall 0x80)
- [x] 8259 PIC remapped to vectors 32–47, PIT timer at ~100 Hz
- [x] Physical Memory Manager (bitmap allocator, 248 MiB tracked)
- [x] Virtual Memory Manager (4-level page table walking)
- [x] Kernel heap allocator (linked-list free-list with coalescing, 8 MiB at 0x400000)
- [x] BSS zeroing on startup (flat binary fix)
- [x] BootInfo handoff at safe address (0x200000, past kernel BSS)
- [x] HAL (port I/O, MSR read/write, interrupt control)

### Phase 2 — Process & Scheduling ✅
- [x] Process Control Block (PCB) — pid, state, cr3, file descriptors, cwd
- [x] Thread Control Block (TCB) — tid, state, CpuContext, kernel stack, wake_tick
- [x] Context switch assembly (callee-saved register save/restore)
- [x] Thread entry trampoline (init_thread_stack + thread_entry_trampoline)
- [x] CoreSched scheduler (round-robin, preemptive, 5-tick quantum / ~50ms)
- [x] Timer-driven scheduling (timer_tick_schedule + check_reschedule)
- [x] Thread sleep/wake with tick-based wakeup
- [x] GDT reordered for SYSRET compatibility (user_data@0x18, user_code@0x20)
- [x] Syscall interface rewritten (int 0x80 + SYSCALL/SYSRET with proper STAR MSR)
- [x] Syscall dispatch with VFS integration (open, read, write, close, getpid, yield)

### Phase 3 — Drivers & I/O ✅
- [x] Serial driver (COM1, 115200 baud)
- [x] Framebuffer console (1024x768, bitmap font rendering)
- [x] PS/2 keyboard driver (Set 1 scancodes, full keyboard with modifiers + extended keys)
- [x] VFS layer (mount table, path resolution, file descriptor ops)
- [x] RamFS (in-memory inode-based filesystem with files + directories)
- [x] Pre-populated filesystem (/dev, /tmp, /home, /bin, /etc, /etc/hostname, /etc/motd)
- [x] IPC subsystem — pipes (ring buffer, 4KiB, R/W/close/eof)
- [x] I/O manager (bridges VFS with kernel devices)

### Phase 4 — Network + Shell ✅
- [x] E1000 NIC driver (Intel 82540EM via PCI, MMIO, DMA ring buffers)
- [x] Ethernet II frame parsing and construction
- [x] ARP protocol (request/reply, ARP cache)
- [x] IPv4 protocol (parsing, routing, checksum, packet construction)
- [x] ICMP protocol (echo request/reply — ping)
- [x] UDP protocol (datagram handling, port binding, send/receive)
- [x] DNS client (recursive resolution via UDP port 53)
- [x] DHCP client (full DORA exchange, lease management)
- [x] TCP protocol (basic state machine — SYN/ACK/FIN/RST)
- [x] Socket abstraction (create, bind, connect, send, recv, close)
- [x] Orbit Shell v0.2 — interactive kernel shell with 50+ commands
- [x] Full keyboard support: arrow keys, Home/End, Delete, Ctrl+A/E/U/K/W/C/L
- [x] Command history with up/down navigation, Tab completion (commands + filenames)
- [x] Inline editing: insert at cursor, cursor movement, partial line operations
- [x] Cursor blinking with timer-based animation
- [x] 9-phase boot sequence — all phases verified in QEMU

### Phase 4.5 — NT Executive Subsystems ✅
- [x] Object Manager (ob/) — hierarchical namespace with \Device, \Driver, \ObjectTypes
- [x] Registry (config/) — HKLM/HKCU hive structure, String/U32/Binary values
- [x] LPC (lpc/) — Local Procedure Call with ports, messages, connection protocol
- [x] Device Manager (io/devmgr.rs) — device tree with hotplug/HW categories
- [x] ProcFS (vfs/procfs.rs) — /proc pseudo-filesystem with /proc/self, /proc/<pid>/*

### Phase 4.6 — Quality & Testing ✅
- [x] Automated test infrastructure (test_runner.rs, run-test.sh)
- [x] QEMU ISA debug-exit device for pass/fail signaling
- [x] Performance metrics subsystem (perf/mod.rs) — interrupt/syscall/heap/context switch counters
- [x] Per-vector interrupt counting (256 vectors)
- [x] Per-syscall invocation counting
- [x] Heap allocation tracking with CAS-loop peak detection
- [x] Instrumented 6 subsystems: IRQ, syscall, scheduler, heap, IDT page faults
- [x] `perf` shell command with summary/irq/syscalls/mem subcommands
- [x] All compiler warnings eliminated (zero warnings in release build)
- [x] 11/11 automated tests passing

### Phase 5 — ELF & User Mode (current)
- [x] ELF64 parser (proc/elf.rs) — validate headers, parse PT_LOAD segments
- [x] ELF loader — map segments with PAGE_USER, allocate user stack at 0x7FFF_FFFF_0000
- [x] Ring 3 transition via IRETQ (proc/usermode.rs)
- [x] Syscall entry rewritten for Ring 3 support (kernel stack switch via SYSCALL_KERNEL_RSP)
- [x] TSS.rsp[0] updated per-thread on context switch (for Ring 3→0 interrupts)
- [x] GDT update_tss_rsp0() function for dynamic kernel stack pointer
- [x] Hand-crafted minimal ELF64 "hello" binary (181 bytes, writes to stdout + exits)
- [x] `exec` shell command to launch ELF binaries in Ring 3
- [x] ELF loader test (Test 11) — validates parsing, mapping, page count
- [x] FAT32 filesystem driver (in-memory, read-only, with VFS integration)
- [x] ATA PIO disk driver (ata.rs — probes all 4 IDE slots, sector read)
- [x] fork_process() — creates child with copied FDs, CWD, separate kernel stack
- [x] waitpid() — reaps zombie children, returns exit code
- [x] fork/exec/waitpid test (Test 14) — full lifecycle verified
- [x] NtStatus error model (shared/ntstatus.rs) — NT-inspired unified error codes
- [x] From conversions: BlockError, VfsError, ElfError → NtStatus
- [x] Full Ring 3 execution with per-process page tables
- [x] Per-process address spaces (separate CR3, CoW fork)
- [x] User-mode page table mapping for Ring 3 ELF execution
- [x] AHCI DMA driver (full FIS-based DMA read/write on Q35)
- [x] Real FAT32 disk mounted at /disk via AHCI port 1
- [x] AhciBlockDevice wrapper implementing BlockDevice trait

### Known Issues / Future Work
- Orbit shell runs in kernel mode — should eventually be a user-mode process
- exec() creates new process instead of replacing current (spawn semantics)
- No argv/envp passing to exec'd processes
- ALPC shared memory views are struct-only (no actual memory mapping yet)
- Win32 subsystem is framework-only (no real Win32 API dispatch)
- Registry has no persistence (in-memory only)
- No SMP / multi-core support

---

## Test Suite Results (21/21 passing)
| # | Test | Status |
|---|------|--------|
| 1 | Network Configuration | ✅ |
| 2 | E1000 Driver Status | ✅ |
| 3 | ARP Resolution (Gateway) | ✅ |
| 4 | Ping Gateway | ✅ |
| 5 | Ping Google DNS (8.8.8.8) | ✅ |
| 6 | DNS Resolution | ✅ |
| 7 | Object Manager Namespace | ✅ |
| 8 | Registry | ✅ |
| 9 | DHCP Client | ✅ |
| 10 | Performance Metrics | ✅ |
| 11 | ELF Loader | ✅ |
| 12 | FAT32 Filesystem | ✅ |
| 13 | ATA PIO Driver | ✅ |
| 14 | exec/fork/waitpid | ✅ |
| 15 | TTY Subsystem | ✅ |
| 16 | FAT32 Write Support | ✅ |
| 17 | Linux Syscall Compat | ✅ |
| 18 | Signal Delivery Trampoline | ✅ |
| 19 | Buffer Cache + File-backed mmap | ✅ |
| 20 | NT Executive Core | ✅ |
| 21 | ALPC + Win32 Subsystem | ✅ |

---

## Changelog

### 2026-02-28 (Session 12) — Milestones 2–7
- **Milestone 2 — TTY/termios Layer**: Full TTY subsystem with Termios, line discipline (canonical/raw), IOCTL support (TCGETS/TCSETS/TIOCGWINSZ), VT100 extensions. 15/15 tests.
- **Milestone 3 — FAT32 Write Support**: Sparse sector cache, dirty tracking, FAT alloc/extend/free, create/write/remove/truncate/mkdir/rmdir, SYS_SYNC. 16/16 tests.
- **Milestone 4 — musl-libc Stubs**: Linux ABI dispatch layer (40+ syscalls), arch_prctl SET_FS, set_tid_address, clock_gettime, writev, openat, getdents64, 144-byte Linux stat. 17/17 tests.
- **Milestone 5 — Signal Delivery Trampoline**: Signal frame on user stack, trampoline page at 0x7FFF_FFFF_F000 (AstryxOS + Linux sigreturn), signal_check_on_syscall_return in asm, sys_sigreturn restores full context, SA_RESTORER support. 18/18 tests.
- **Milestone 6 — Buffer Cache + File-backed mmap**: Global page cache (mm/cache.rs), file-backed mmap with demand paging from VFS, munmap with refcount-based page freeing, cache coherency for shared pages. 19/19 tests.
- **Milestone 7 — Full NT Executive**:
  - *Part A*: KernelObject trait, OB overhaul (insert/lookup/remove/symlink/SD), per-process Handle Table (NT-style multiples of 4), IRP-based I/O Manager (9 major functions, DriverObject/DeviceObject, 4 built-in drivers), security check_object_access integration. 20/20 tests.
  - *Part B*: ALPC (AlpcMessage with msg_id, Request/Reply/Datagram types, server accept flow, port security, view stubs, OB registration, legacy compat), Win32 subsystem (SubsystemType enum, Win32Environment, CsrApiPort, WinSta0/Desktop creation, subsystem registry, CsrApiNumber). 21/21 tests.

### 2026-02-28 (Session 11) — Milestone 1
- **Per-process Page Tables**: Each user process gets its own CR3/PML4
  - refcount::init() now called at boot for CoW page frame tracking
  - Scheduler switches CR3 when switching between processes
  - ELF loader maps into process-specific page table via map_page_in()
  - ELF loader creates VMAs for each PT_LOAD segment + user stack
  - create_user_process() allocates VmSpace::new_user() with unique CR3
- **CoW Fork**: fork_process() uses VmSpace::clone_for_fork()
  - Parent/child get separate CR3 values 
  - User pages marked read-only in both, refcount incremented
  - Page fault handler copies on write (refcount > 1 → copy, remap writable)
- **Exec Improvements**: sys_exec() creates process with per-process page tables
- **AHCI Persistent Disk**: Full AHCI DMA driver, 64MB FAT32 disk at /disk
  - AhciBlockDevice implementing BlockDevice trait
  - init_ahci_fat32() probes AHCI ports, mounts FAT32 at /disk
- **External Ping Fixed**: sysctl detection bug in run-test.sh/run-qemu.sh
- 14/14 tests passing (including per-process page table + CoW verification)

### 2026-02-28 (Session 10)
- **NtStatus Error Model**: Created shared/src/ntstatus.rs (~500 lines)
  - NT-inspired unified error type: `NtStatus(i32)` with `#[repr(transparent)]`
  - Bit layout: Severity(31-30), Customer(29), Reserved(28), Facility(27-16), Code(15-0)
  - 16 facility codes for kernel subsystems (IO, Process, Memory, Network, FS, Image, IPC, etc.)
  - ~65 status code constants matching Windows NT conventions + AstryxOS-specific codes
  - Methods: is_success(), is_error(), severity(), facility(), code(), name(), to_result()
  - Debug/Display impls with human-readable names for all defined codes
  - NtResult<T> = Result<T, NtStatus> convenience alias
  - From<BlockError>, From<VfsError>, From<ElfError> → NtStatus conversions
- **Context Switch Fix**: Rewrote switch_context from inline asm to global_asm!
  - **Root cause**: inline asm with `ret` was being inlined into schedule(), causing the
    `ret` to pop the compiler's own pushed rbp (a stack address) instead of the actual
    return address, resulting in Invalid Opcode (executing stack memory as code)
  - Fixed by using `global_asm!` to define switch_context_asm as a real symbol — no
    compiler prologue/epilogue, impossible to inline
  - Also fixed stack alignment: added padding in init_thread_stack so RSP mod 16 == 8
    on trampoline entry (System V AMD64 ABI requirement)
- **fork_child_entry**: Reverted cli/sti workarounds; simple exit_thread(0) now works
- **Test 14 (exec/fork/waitpid)**: Now fully passes — fork, child execution, exit, waitpid
  reap all verified. Ring 3 exec skipped in test mode (page table mapping pending).
- **14/14 tests passing**, zero build warnings
- Source files: ~54 kernel modules

### 2026-02-27 (Session 9)
- **FAT32 Filesystem Driver**: Created drivers/fat32.rs (~450 lines)
  - BPB/FAT parsing, cluster chain traversal, 8.3 filename decoding
  - Integrated with VFS via vfs/fat32_vfs.rs adapter
  - In-memory operation: reads entire image from BlockDevice at mount time
  - Recursive directory discovery, proper FAT32 root cluster traversal
- **ATA PIO Driver**: Created drivers/ata.rs (~310 lines)
  - Probes all 4 IDE slots (Primary/Secondary × Master/Slave)
  - IDENTIFY command, PIO sector read via ports 0x1F0/0x170
  - BlockDevice trait implementation for ATA drives
- **exec/fork/waitpid Syscalls**: Implemented in proc/mod.rs + syscall/mod.rs
  - fork_process(): creates child with separate kernel stack, copied FDs/CWD
  - fork_child_entry(): trampoline for forked child execution
  - waitpid(): reaps zombie children, returns (pid, exit_code)
  - SYS_EXEC, SYS_FORK, SYS_WAITPID dispatch in syscall table
- **Real Data Disk**: Created fat32-test.img via mkfs.fat, attached in QEMU as IDE secondary
- **QEMU Script Updates**: Updated run-qemu.sh and run-test.sh for data disk attachment
- **Tests 12-14**: FAT32, ATA PIO, exec/fork/waitpid — all passing (14/14 total)

### 2026-02-27 (Session 8)
- **ELF64 Loader**: Created proc/elf.rs — full ELF64 parser with PT_LOAD segment loading
- **Ring 3 Transition**: Created proc/usermode.rs — IRETQ-based user mode entry, bootstrap
- **Syscall Rewrite**: Fixed syscall_entry for Ring 3→0 stack switching
  - Added SYSCALL_KERNEL_RSP/SYSCALL_USER_RSP globals for manual stack swap
  - Fixed double-argument-rearrangement bug in original syscall_entry
  - Proper callee-saved register preservation across syscall boundary
  - STI/CLI around dispatch for interrupt handling during syscalls
- **Scheduler Update**: TSS.rsp[0] and SYSCALL_KERNEL_RSP updated on every context switch
- **GDT Enhancement**: Added update_tss_rsp0() for dynamic per-thread kernel stack
- **Embedded User Binary**: Hand-crafted 181-byte ELF64 "hello" (proc/hello_elf.rs)
- **Shell**: Added `exec` command to load and run ELF binaries in Ring 3
- **Test 11**: ELF loader validation — header parsing, segment mapping, page allocation
- **Build**: Zero warnings, 11/11 tests passing
- Source files: 49 kernel modules

### 2026-02-27 (Session 7)
- **Performance Metrics Subsystem**: Created perf/mod.rs (~260 lines)
  - Per-vector interrupt counters (256 vectors), per-syscall counters (16 slots)
  - Context switch counter, idle tick counter, page fault counter
  - Heap alloc/free counters with CAS-loop peak tracking
  - PerfSnapshot aggregation with net stats and uptime
- **Instrumented 6 subsystems**: timer_tick (IRQ 32), keyboard (IRQ 33), syscall dispatch,
  scheduler (context switch + idle tick), heap GlobalAlloc (alloc/free), IDT page fault handler
- **Shell**: Added `perf` command with 4 subcommands (summary, irq, syscalls, mem)
- **Test 10**: Performance metrics test — validates timer > 0, heap allocs > 0, uptime > 0
- **Warning Elimination**: Reduced compiler warnings from ~158 to ZERO
- **Sudo Fix**: Fixed run-test.sh sudo sysctl to try-without-sudo first
- Build verified: 10/10 tests passing, zero warnings

### 2026-02-26 (Session 6)
- **Keyboard v2**: Full PS/2 keyboard with modifier tracking, extended keys (arrows, Home/End,
  Delete, PgUp/PgDn), Ctrl+key combos, key event enum
- **Console v2**: Cursor management (show/hide/blink), partial line clear, cursor positioning
- **Shell v0.2**: Inline cursor editing, arrow key navigation, Ctrl+A/E/U/K/W/C/L,
  Delete key, Home/End, word deletion, improved tab completion with file type indicators
- **6 New Kernel Modules**:
  - dns/mod.rs — DNS client (A/AAAA query construction, response parsing, recursive resolution)
  - ob/mod.rs — Object Manager (NT-style hierarchical namespace)
  - config/mod.rs — Registry subsystem (HKLM/HKCU hives, String/U32/Binary types)
  - lpc/mod.rs — LPC facility (ports, messages, connection protocol)
  - vfs/procfs.rs — ProcFS (/proc pseudo-filesystem)
  - io/devmgr.rs — Device Manager (device tree, hotplug, categories)
- **Phase 9 Boot**: Added NT Executive subsystem init phase
- 3 new tests: Object Manager, Registry, DNS Resolution (9/9 passing)

### 2026-02-26 (Session 5)
- **E1000 NIC Driver**: Full Intel 82540EM driver via PCI MMIO
  - PCI enumeration, BAR0 MMIO mapping, TX/RX ring buffers (16 descriptors each)
  - Interrupt-driven receive, descriptor-based transmit
- **Full Network Stack**: ARP, IPv4, ICMP, UDP with proper checksums
- **DHCP Client**: Full DORA exchange (Discover → Offer → Request → Ack)
- **Automated Test Infrastructure**: 9 tests covering network, OB, registry, DHCP
- 9/9 tests passing

### 2026-02-26 (Session 4)
- Created remaining network protocol files (arp, ipv4, icmp, udp, tcp, socket)
- Updated main.rs with vfs, ipc, net, shell module declarations
- Added Phase 7 (VFS+IPC) and Phase 8 (Network) to boot sequence
- Updated I/O module to integrate with VFS
- Built Orbit Shell v0.1 — feature-rich kernel shell replacing basic kernel_shell
  - 30+ commands covering files, processes, networking, IPC, system info
  - Working directory support (cd, pwd)
  - Path resolution (relative + absolute paths)
  - Command history
  - Directory tree display
  - Hexdump, file stat, pipe testing
- Made Console methods pub for shell access
- Fixed compilation errors (Display impl for readdir, write_file return type)
- Full build verified — all 8 boot phases pass in QEMU
- Updated PROGRESS.md

### 2026-02-26 (Session 3)
- Rewrote heap allocator from bump to linked-list free-list with proper dealloc + coalescing
- Rewrote proc/mod.rs — separate Thread/Process model with TCB/PCB
- Created proc/thread.rs — context switch assembly, thread_entry_trampoline, init_thread_stack
- Rewrote sched/mod.rs — round-robin scheduler with preemptive time slicing
- Fixed GDT segment order for SYSRET compatibility
- Rewrote syscall/mod.rs — proper STAR MSR, dispatch with VFS integration
- Fixed IDT to route int 0x80 to dedicated syscall handler
- Created VFS layer (vfs/mod.rs) — mount table, path resolution, file descriptors
- Created RamFS (vfs/ramfs.rs) — inode-based in-memory filesystem
- Created IPC subsystem (ipc/mod.rs, ipc/pipe.rs) — ring buffer pipes
- Started network stack (net/mod.rs, net/virtio_net.rs, net/ethernet.rs)

### 2026-02-26 (Session 2)
- Fixed uefi 0.34 API changes (boot::*, system::with_stdout(), etc.)
- Fixed Rust 2024 naked function syntax (#[unsafe(naked)] + naked_asm!)
- Fixed custom target JSON (target-pointer-width, rustc-abi, linker-flavor)
- Fixed BootInfo/BSS overlap — moved BootInfo to 0x200000 (2 MiB)
- Added BSS zeroing in kernel _start before any static variable use
- Added serial debug output throughout kernel init phases
- Full boot verified in QEMU: all 7 kernel phases initialize successfully
- Build produces both .img and .iso artifacts

### 2026-02-26 (Session 1)
- Project initialized
- `.ai/` folder created with STYLE_GUIDE.md, PLAN.md, PROGRESS.md
- Architecture decision: NT-inspired monolithic kernel
- All source files created for bootloader, kernel, and shared crate
