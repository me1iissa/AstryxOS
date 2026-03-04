//! AstryxOS Shared Types
//!
//! Types shared between the bootloader (AstryxBoot) and the kernel (Aether).
//! These structures define the ABI contract for boot information handoff.

#![no_std]

pub mod ntstatus;

/// Re-export the core status type for convenience.
pub use ntstatus::{NtStatus, NtResult};

/// Magic number to validate BootInfo integrity.
pub const BOOT_INFO_MAGIC: u64 = 0x4153_5452_5958_4F53; // "ASTRYXOS" in hex-ish

/// Kernel load physical address.
pub const KERNEL_PHYS_BASE: u64 = 0x10_0000; // 1 MiB

/// Fixed physical address for BootInfo handoff.
/// Placed at 3 MiB — safely past kernel .text/.data/.bss (BSS ends ~0x209000).
pub const BOOT_INFO_PHYS_BASE: u64 = 0x30_0000; // 3 MiB

/// Higher-half virtual base for the kernel.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Maximum number of memory map entries we support.
pub const MAX_MEMORY_MAP_ENTRIES: usize = 256;

/// Boot information passed from AstryxBoot to Aether kernel.
///
/// This structure is placed at a known physical address and its pointer
/// is passed to the kernel entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    /// Magic number for validation.
    pub magic: u64,
    /// Framebuffer information.
    pub framebuffer: FramebufferInfo,
    /// Memory map from UEFI.
    pub memory_map: MemoryMapInfo,
    /// Physical address of ACPI RSDP table, 0 if not found.
    pub rsdp_address: u64,
    /// Physical address where the kernel was loaded.
    pub kernel_phys_base: u64,
    /// Size of the kernel binary in bytes.
    pub kernel_size: u64,
}

/// Framebuffer information from UEFI GOP.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical base address of the framebuffer.
    pub base_address: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Stride (pixels per scanline, may be > width).
    pub stride: u32,
    /// Bytes per pixel (typically 4 for 32-bit color).
    pub bytes_per_pixel: u32,
    /// Pixel format.
    pub pixel_format: PixelFormat,
}

/// Pixel format of the framebuffer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// Blue, Green, Red, Reserved (BGRA).
    Bgr = 0,
    /// Red, Green, Blue, Reserved (RGBA).
    Rgb = 1,
    /// Unknown/bitmask format.
    Unknown = 2,
}

/// Memory map information.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapInfo {
    /// Inline array of memory map entries.
    pub entries: [MemoryMapEntry; MAX_MEMORY_MAP_ENTRIES],
    /// Number of valid entries.
    pub entry_count: u64,
}

/// A single memory map entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    /// Type of this memory region.
    pub memory_type: MemoryType,
    /// Physical start address (page-aligned).
    pub physical_start: u64,
    /// Number of 4 KiB pages in this region.
    pub page_count: u64,
}

/// Memory region types (simplified from UEFI memory types).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// Reserved, do not use.
    Reserved = 0,
    /// Available for general use.
    Available = 1,
    /// ACPI reclaimable memory.
    AcpiReclaimable = 2,
    /// ACPI NVS memory.
    AcpiNvs = 3,
    /// Memory used by the kernel.
    Kernel = 4,
    /// Memory used by the bootloader.
    Bootloader = 5,
    /// Framebuffer memory.
    Framebuffer = 6,
}

/// Syscall numbers shared between kernel and userspace.
pub mod syscall {
    pub const SYS_EXIT: u64 = 0;
    pub const SYS_WRITE: u64 = 1;
    pub const SYS_READ: u64 = 2;
    pub const SYS_OPEN: u64 = 3;
    pub const SYS_CLOSE: u64 = 4;
    pub const SYS_FORK: u64 = 5;
    pub const SYS_EXEC: u64 = 6;
    pub const SYS_WAITPID: u64 = 7;
    pub const SYS_GETPID: u64 = 8;
    pub const SYS_MMAP: u64 = 9;
    pub const SYS_MUNMAP: u64 = 10;
    pub const SYS_BRK: u64 = 11;
    pub const SYS_IOCTL: u64 = 12;
    pub const SYS_YIELD: u64 = 13;

    // ── Quick-win POSIX syscalls ────────────────────────────────
    pub const SYS_GETPPID: u64 = 14;
    pub const SYS_GETCWD: u64 = 15;
    pub const SYS_CHDIR: u64 = 16;
    pub const SYS_MKDIR: u64 = 17;
    pub const SYS_RMDIR: u64 = 18;
    pub const SYS_STAT: u64 = 19;
    pub const SYS_FSTAT: u64 = 20;
    pub const SYS_LSEEK: u64 = 21;
    pub const SYS_DUP: u64 = 22;
    pub const SYS_DUP2: u64 = 23;
    pub const SYS_PIPE: u64 = 24;
    pub const SYS_UNAME: u64 = 25;
    pub const SYS_NANOSLEEP: u64 = 26;
    pub const SYS_GETUID: u64 = 27;
    pub const SYS_GETGID: u64 = 28;
    pub const SYS_GETEUID: u64 = 29;
    pub const SYS_GETEGID: u64 = 30;
    pub const SYS_UMASK: u64 = 31;
    pub const SYS_CHMOD: u64 = 32;
    pub const SYS_CHOWN: u64 = 33;
    pub const SYS_UNLINK: u64 = 34;
    pub const SYS_GETRANDOM: u64 = 35;
    pub const SYS_KILL: u64 = 36;
    pub const SYS_SIGACTION: u64 = 37;
    pub const SYS_SIGPROCMASK: u64 = 38;
    pub const SYS_SIGRETURN: u64 = 39;

    // ── Networking / Threading syscalls ───────────────────────
    pub const SYS_SOCKET: u64 = 40;
    pub const SYS_BIND: u64 = 41;
    pub const SYS_CONNECT: u64 = 42;
    pub const SYS_SENDTO: u64 = 43;
    pub const SYS_RECVFROM: u64 = 44;
    pub const SYS_LISTEN: u64 = 45;
    pub const SYS_ACCEPT: u64 = 46;
    pub const SYS_CLONE: u64 = 47;
    pub const SYS_FUTEX: u64 = 48;
    pub const SYS_SYNC: u64 = 49;
}
