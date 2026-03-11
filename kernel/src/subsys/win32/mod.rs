//! Win32/WoW Compatibility Subsystem
//!
//! Translates Win32 NT syscalls to Aether equivalents.
//! Processes with `SubsystemType::Win32` use this personality.
//!
//! # Architecture
//! Win32 processes enter via INT 0x2E (legacy) or SYSCALL (modern ntdll).
//! The SSDT (System Service Dispatch Table) maps NT syscall numbers to
//! Aether kernel functions. NT object handles are backed by the Aether
//! Object Manager and Handle Table infrastructure.
//!
//! # Current State
//! The executive framework lives in `kernel/src/win32/mod.rs`:
//! - `SubsystemType` enum (Native, Aether, Linux, Win32)
//! - `SubsystemContext` per-process state
//! - `Win32Environment` (desktop, window station, process heap)
//! - CSRSS skeleton with ALPC port `\ALPC\CsrApiPort`
//! - WinSta0 and Default desktop in Object Manager namespace
//! - Subsystem registry with active/inactive state
//!
//! # Phase 0.3 Plan (P0 items)
//! 1. PE loader: parse DOS/PE headers, map sections, apply relocations, build IAT
//! 2. ntdll.dll stubs: NtTerminateProcess, NtWriteFile, NtClose, RtlInit*
//! 3. SSDT: ~30 NT syscalls mapped to Aether handlers
//! 4. kernel32.dll stubs: WriteConsoleA/W, ExitProcess, GetStdHandle
//!
//! See `.ai/subsystem/WIN32.md` for full design and SSDT table.
//! See `kernel/src/win32/mod.rs` for the existing executive framework.

// Executive framework is in kernel/src/win32/mod.rs
// PE loader and SSDT to be implemented here.
// Migration tracked in .ai/subsystem/PLAN.md Phase 0.3
