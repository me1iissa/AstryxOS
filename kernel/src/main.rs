//! Aether — The AstryxOS Kernel (v0.1, codename Aether)
//!
//! This is the core kernel of AstryxOS, inspired by the Windows NT executive
//! architecture with clean subsystem boundaries in a monolithic kernel design.
//!
//! # Subsystems
//! - **HAL** — Hardware Abstraction Layer
//! - **MM** — Memory Manager (PMM + VMM + Heap)
//! - **Proc** — Process Manager
//! - **Sched** — CoreSched Scheduler
//! - **Syscall** — System Call Interface
//! - **IO** — I/O Manager
//! - **Drivers** — Device Drivers

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![allow(dead_code, unused_imports)]

mod arch;
mod config;
mod drivers;
mod ex;
mod hal;
mod io;
mod ipc;
mod ke;
mod lpc;
mod mm;
mod net;
mod ob;
mod perf;
mod po;
mod proc;
mod sched;
mod security;
mod signal;
mod shell;
mod syscall;
#[cfg(feature = "test-mode")]
mod test_runner;
mod gdi;
mod gui;
mod msg;
mod vfs;
mod wm;
mod win32;

use astryx_shared::{BootInfo, BOOT_INFO_MAGIC};

extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
}

/// Kernel entry point — called by AstryxBoot after setting up page tables.
///
/// # Arguments
/// * `boot_info` — Pointer to the BootInfo structure prepared by the bootloader.
///
/// # Safety
/// This function is the kernel entry point, called directly by the bootloader
/// via a jump. It must be at the start of the .text section.
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start(boot_info: *const BootInfo) -> ! {
    // Zero BSS — the flat binary does not include the .bss section,
    // so we must clear it ourselves before using any static variables.
    {
        let bss_start = &raw const __bss_start as *mut u8;
        let bss_end = &raw const __bss_end as *const u8;
        let bss_len = bss_end as usize - bss_start as usize;
        core::ptr::write_bytes(bss_start, 0, bss_len);
    }

    // Initialize serial first for debug output
    drivers::serial::init();
    serial_println!("[Aether] Serial port initialized");

    // Validate boot info
    serial_println!("[Aether] Validating BootInfo at {:p}", boot_info);
    let info = &*boot_info;
    assert_eq!(info.magic, BOOT_INFO_MAGIC, "Invalid BootInfo magic");
    serial_println!("[Aether] BootInfo magic validated OK");

    // Phase 1: Hardware Abstraction Layer
    serial_println!("[Aether] Phase 1: HAL init...");
    hal::init();
    serial_println!("[Aether] Phase 1: HAL OK");

    // Phase 2: Architecture-specific init (GDT, IDT, IRQ)
    serial_println!("[Aether] Phase 2: x86_64 arch init...");
    arch::x86_64::init();
    serial_println!("[Aether] Phase 2: x86_64 arch OK");

    // Phase 3: Memory management (PMM, VMM, heap)
    serial_println!("[Aether] Phase 3: Memory management init...");
    mm::init(info);
    mm::refcount::init();
    serial_println!("[Aether] Phase 3: Memory management OK");

    // Phase 4: Initialize drivers
    serial_println!("[Aether] Phase 4: Driver init...");
    drivers::init(info);
    serial_println!("[Aether] Phase 4: Drivers OK");

    // Phase 4b: Kernel Executive (IRQL, DPC, APC)
    serial_println!("[Aether] Phase 4b: Kernel Executive init...");
    ke::init();
    serial_println!("[Aether] Phase 4b: Kernel Executive OK");

    // Phase 4c: Executive Services (EResource, FastMutex, PushLock, WorkQueues)
    serial_println!("[Aether] Phase 4c: Executive Services init...");
    ex::init();
    serial_println!("[Aether] Phase 4c: Executive Services OK");

    // Phase 5: Process manager and scheduler
    serial_println!("[Aether] Phase 5: Process & scheduler init...");
    proc::init();
    sched::init();
    serial_println!("[Aether] Phase 5: Process & scheduler OK");

    // Phase 5b: APIC and SMP
    serial_println!("[Aether] Phase 5b: APIC init...");
    arch::x86_64::apic::init();
    arch::x86_64::apic::start_aps();
    serial_println!("[Aether] Phase 5b: APIC OK");

    // Phase 6: Syscall interface
    serial_println!("[Aether] Phase 6: Syscall init...");
    syscall::init();
    serial_println!("[Aether] Phase 6: Syscall OK");

    // Phase 7: VFS, IPC, and I/O subsystem
    serial_println!("[Aether] Phase 7: VFS, IPC & I/O subsystem init...");
    vfs::init();
    serial_println!("[Aether] Phase 7a: VFS OK");
    vfs::init_fat32();
    serial_println!("[Aether] Phase 7a: FAT32 OK");
    vfs::ext2::try_mount();
    serial_println!("[Aether] Phase 7a: ext2 OK");
    ipc::init();
    serial_println!("[Aether] Phase 7b: IPC OK");
    io::init();
    serial_println!("[Aether] Phase 7: I/O subsystem OK");

    // Phase 8: Networking
    serial_println!("[Aether] Phase 8: Network init...");
    net::init();
    serial_println!("[Aether] Phase 8: Network OK");

    // Phase 9: NT Executive subsystems
    serial_println!("[Aether] Phase 9: NT Executive subsystems init...");
    ob::init();
    serial_println!("[Aether] Phase 9a: Object Manager OK");
    security::init();
    serial_println!("[Aether] Phase 9b: Security subsystem OK");
    signal::init();
    serial_println!("[Aether] Phase 9b: Signal subsystem OK");
    config::init();
    serial_println!("[Aether] Phase 9c: Registry OK");
    lpc::init();
    serial_println!("[Aether] Phase 9c: LPC OK");
    win32::init();
    serial_println!("[Aether] Phase 9d: Win32 subsystem OK");
    serial_println!("[Aether] Phase 9: NT Executive OK");

    // Phase 9e: Power management
    serial_println!("[Aether] Phase 9e: Power management init...");
    po::init();
    serial_println!("[Aether] Phase 9e: Power management OK");

    // Phase 10: Display & GUI subsystem
    // Probe SVGA first so we can use its framebuffer for everything.
    serial_println!("[Aether] Phase 10a: VMware SVGA II init...");
    let svga_ok = drivers::vmware_svga::init();
    serial_println!("[Aether] Phase 10a: VMware SVGA II {}", if svga_ok { "OK" } else { "not available (using fallback FB)" });

    // Determine actual framebuffer parameters
    let (fb_base, fb_width, fb_height, fb_stride) = if svga_ok {
        if let Some(params) = drivers::vmware_svga::get_framebuffer() {
            params
        } else {
            (info.framebuffer.base_address, info.framebuffer.width,
             info.framebuffer.height, info.framebuffer.stride)
        }
    } else {
        (info.framebuffer.base_address, info.framebuffer.width,
         info.framebuffer.height, info.framebuffer.stride)
    };

    serial_println!("[Aether] Display: {}x{} fb=0x{:x} stride={}", fb_width, fb_height, fb_base, fb_stride);

    // Reconfigure console to use the active framebuffer
    if svga_ok {
        drivers::console::reconfigure_framebuffer(fb_base, fb_width, fb_height, fb_stride);
        drivers::mouse::set_bounds(fb_width, fb_height);
    }

    // Phase 10b: GUI compositor (with correct framebuffer)
    serial_println!("[Aether] Phase 10b: GUI init...");
    gui::init(fb_base, fb_width, fb_height, fb_stride);
    serial_println!("[Aether] Phase 10b: GUI OK");

    // Phase 10c: GDI engine
    serial_println!("[Aether] Phase 10c: GDI init...");
    gdi::init();
    serial_println!("[Aether] Phase 10c: GDI OK");

    // Phase 10d: Window Manager (with correct resolution)
    serial_println!("[Aether] Phase 10d: Window Manager init...");
    wm::init(fb_width, fb_height);
    serial_println!("[Aether] Phase 10d: Window Manager OK");

    // Phase 10e: Message System
    serial_println!("[Aether] Phase 10e: Message System init...");
    msg::init();
    serial_println!("[Aether] Phase 10e: Message System OK");

    // Phase 10f: GUI input pump
    serial_println!("[Aether] Phase 10f: GUI input init...");
    gui::input::init();
    serial_println!("[Aether] Phase 10f: GUI input OK");

    // Print welcome message to both serial and framebuffer
    let banner = "========================================";
    serial_println!("{}", banner);
    serial_println!("  AstryxOS - Aether Kernel v0.1");
    serial_println!("  Architecture: x86_64 (UEFI)");
    serial_println!("  Framebuffer: {}x{}", info.framebuffer.width, info.framebuffer.height);
    serial_println!("  Memory regions: {}", info.memory_map.entry_count);
    serial_println!("{}", banner);
    serial_println!("");
    serial_println!("[Aether] Kernel initialization complete.");
    serial_println!("[Aether] Dropping to kernel shell...");
    serial_println!("");

    kprintln!("========================================");
    kprintln!("  AstryxOS - Aether Kernel v0.1");
    kprintln!("  Architecture: x86_64 (UEFI)");
    kprintln!("  Framebuffer: {}x{}", info.framebuffer.width, info.framebuffer.height);
    kprintln!("  Memory regions: {}", info.memory_map.entry_count);
    kprintln!("========================================");
    kprintln!("");
    kprintln!("[Aether] Kernel initialization complete.");
    kprintln!("[Aether] Dropping to kernel shell...");
    kprintln!("");

    // In test mode, run the automated test suite instead of the shell.
    // In normal mode, launch the interactive Orbit shell.
    #[cfg(feature = "test-mode")]
    {
        serial_println!("[Aether] TEST MODE — launching automated test suite");
        test_runner::run()
    }

    #[cfg(not(feature = "test-mode"))]
    {
        // Phase 13: Launch Ascension (init) and Orbit (shell) as Ring 3 processes
        serial_println!("[Aether] Phase 13: Launching userspace processes...");

        // Launch Ascension — the init process (PID 1 equivalent)
        serial_println!("[Aether] Launching Ascension (init)...");
        match proc::usermode::create_user_process("ascension", &proc::ascension_elf::ASCENSION_ELF) {
            Ok(pid) => serial_println!("[Aether] Ascension launched as PID {}", pid),
            Err(e) => serial_println!("[Aether] Failed to launch Ascension: {:?}", e),
        }

        // Launch Orbit — the user-mode shell
        serial_println!("[Aether] Launching Orbit (shell)...");
        match proc::usermode::create_user_process("orbit", &proc::orbit_elf::ORBIT_ELF) {
            Ok(pid) => serial_println!("[Aether] Orbit launched as PID {}", pid),
            Err(e) => serial_println!("[Aether] Failed to launch Orbit: {:?}", e),
        }

        serial_println!("[Aether] Phase 13: Userspace processes launched.");

        // Drop to the kernel shell for interactive debugging/management.
        // In the future, the kernel shell may be removed once Orbit is fully
        // interactive and can be reached via serial/console.
        shell::launch()
    }
}

/// Kernel panic handler.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Try to print to serial port
    serial_println!("\n!!! KERNEL PANIC !!!");
    serial_println!("{}", info);

    // Also try framebuffer console
    kprintln!("\n!!! KERNEL PANIC !!!");
    kprintln!("{}", info);

    // Halt the CPU
    loop {
        unsafe {
            core::arch::asm!("cli; hlt");
        }
    }
}

/// Kernel print macros.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::drivers::console::_kprint(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)))
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::drivers::serial::_serial_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)))
}
