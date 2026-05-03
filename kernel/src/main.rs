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
mod nt;
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
#[cfg(feature = "kdb")]
mod kdb;
mod msg;
mod vfs;
mod wm;
mod win32;
mod subsys;
mod x11;
mod init;
mod util;

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
    let _idle_stack_top = proc::init();
    sched::init();
    serial_println!("[Aether] Phase 5: Process & scheduler OK");

    // NOTE: We do NOT switch the BSP stack here.  The UEFI bootstrap stack
    // remains active for kernel_main.  It is in the identity-mapped region
    // (PML4[0]) which would become unmapped if schedule() switched CR3 to a
    // user page table.  The fix is in schedule(): the Phase 1 CR3 switch to
    // kernel_cr3 before switch_context ensures the identity map stays active
    // for the bootstrap stack.  TID 0's higher-half kernel_stack_base/size
    // are still used for TSS.RSP[0] and per_cpu.kernel_rsp by the scheduler.

    // Phase 5b: APIC and SMP
    serial_println!("[Aether] Phase 5b: APIC init...");
    arch::x86_64::apic::init();
    arch::x86_64::apic::start_aps();
    // Now that the IO-APIC is live, route the virtio-blk legacy INTx line
    // to its IDT vector.  Any virtio-blk reads issued before this point
    // (none today, but keep in mind for future early-FS code) use the
    // poll fallback, see drivers/virtio_blk.rs::submit_request.
    drivers::virtio_blk::arm_irq();
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

    // Phase 8b: kdb TCP introspection server (feature-gated).
    // Must run after net::init() because it calls tcp::listen().
    #[cfg(feature = "kdb")]
    {
        serial_println!("[Aether] Phase 8b: kdb introspection server init...");
        kdb::init();
        serial_println!("[Aether] Phase 8b: kdb OK");
    }

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
        // ── GUI-TEST mode: bounded desktop loop → pixel telemetry → exit ──
        // This branch runs the full compositor and window manager for 60 timer
        // ticks, samples key pixels from the backbuffer, emits them to serial,
        // then triggers QEMU's ISA debug-exit port so the test script can pick
        // up the exit code.  It does NOT launch any userspace processes.
        #[cfg(feature = "gui-test")]
        {
            serial_println!("[Aether] GUI-TEST MODE — running bounded desktop loop...");
            let frames = gui::desktop::launch_desktop_with_timeout(60);
            gui::compositor::emit_pixel_telemetry();
            serial_println!("[GUITEST] DONE frames={}", frames);
            // Give the run script ~1 second to issue a QMP screendump before
            // we pull the plug — we wait for ~100 timer ticks then exit via
            // the ISA debug-exit device (value 0 → QEMU exit code 1 = pass).
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 100 {
                core::hint::spin_loop();
            }
            unsafe {
                core::arch::asm!(
                    "out dx, eax",
                    in("dx")  0xf4_u16,  // ISA debug-exit iobase
                    in("eax") 0_u32,     // value 0 → exit(1) = pass
                    options(nomem, nostack)
                );
            }
            loop { unsafe { core::arch::asm!("hlt"); } }
        }

        // ── X11 visual test: create a colored window and hold it on screen ──
        // Activated by firefox-test mode — shows an X11 window before Firefox.
        #[cfg(all(not(feature = "gui-test"), feature = "firefox-test"))]
        {
            serial_println!("[FFTEST] Firefox-test mode starting...");
            x11::init();
            serial_println!("[FFTEST] X11 server ready");

            // Create a visible X11 test window BEFORE Firefox launches
            serial_println!("[X11-VIS] Creating X11 visual test window...");
            {
                use crate::net::unix;
                let cfd = unix::create();
                if cfd != u64::MAX && unix::connect(cfd, b"/tmp/.X11-unix/X0\0") >= 0 {
                    // X11 connection setup
                    let hello: [u8; 12] = [0x6C, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                    unix::write(cfd, &hello);
                    x11::poll();
                    let mut buf = [0u8; 256];
                    unix::read(cfd, &mut buf);

                    // CreateWindow: 200×150 at (100,100), bright cyan background 0x00A0C0
                    let mut cw = [0u8; 40];
                    cw[0] = 1; // CreateWindow
                    cw[2] = 10; cw[3] = 0; // length=10 words
                    // wid = 0x700001
                    cw[4] = 0x01; cw[5] = 0x00; cw[6] = 0x70; cw[7] = 0x00;
                    // parent = root (1)
                    cw[8] = 0x01; cw[9] = 0x00; cw[10] = 0x00; cw[11] = 0x00;
                    // x=100, y=100
                    cw[12] = 100; cw[13] = 0; cw[14] = 100; cw[15] = 0;
                    // w=300, h=200
                    cw[16] = 0x2C; cw[17] = 0x01; // 300
                    cw[18] = 0xC8; cw[19] = 0x00; // 200
                    // border=0, class=1
                    cw[22] = 1; cw[23] = 0;
                    // visual = 32
                    cw[24] = 32; cw[25] = 0;
                    // vmask = CW_BACK_PIXEL(0x02)
                    cw[28] = 0x02;
                    // bg_pixel = 0x00A0C0 (bright teal/cyan)
                    cw[32] = 0xC0; cw[33] = 0xA0; cw[34] = 0x00; cw[35] = 0x00;
                    unix::write(cfd, &cw);
                    x11::poll();

                    // MapWindow
                    let map: [u8; 8] = [8, 0, 2, 0, 0x01, 0x00, 0x70, 0x00];
                    unix::write(cfd, &map);
                    x11::poll();

                    serial_println!("[X11-VIS] Created 300x200 window at (100,100) with cyan bg");

                    // DON'T close the connection — keep the window alive
                    // It will persist until Firefox test ends
                }
            }
            gui::desktop::launch_desktop();
            hal::enable_interrupts();

            // Wait 30 ticks for the desktop to settle before launching Firefox.
            // Use spin-wait (not hlt) — LAPIC timer delivery after MMIO exits is unreliable.
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                gui::compositor::compose();
                core::hint::spin_loop();
            }

            // Pre-load key files into the VFS read cache BEFORE launching Firefox.
            // ATA PIO on WSL2/KVM is ~100µs per sector (nested virt exit), making
            // the 2.7MB firefox-bin + 300KB ld-linux take 5+ minutes cold. By pre-loading
            // here, the desktop compositor can spin while we wait, and the actual
            // Firefox exec is instant (cache hit).
            // Pre-allocate kernel stacks BEFORE filling the page cache.
            // The page cache will fragment the PMM bitmap, making contiguous
            // 16-page (64KB) kernel stack allocations fail. By pre-allocating
            // stacks now, they're available from the dead-stack cache later.
            {
                const PRE_ALLOC_STACKS: usize = 32;
                let mut prealloc_count = 0;
                for _ in 0..PRE_ALLOC_STACKS {
                    if let Some(phys) = mm::pmm::alloc_pages(proc::KERNEL_STACK_PAGES_PUB) {
                        let base = proc::KERNEL_VIRT_OFFSET + phys;
                        proc::write_stack_canary(base);
                        sched::push_dead_stack_pub(base);
                        prealloc_count += 1;
                    }
                }
                serial_println!("[FFTEST] Pre-allocated {} kernel stacks ({} KiB)",
                    prealloc_count, prealloc_count * 64);
            }

            // Pre-populate the PAGE CACHE for key Firefox files.
            // This reads every 4KB page from disk into PMM-allocated pages
            // and inserts them into the global page cache.  When ld-linux
            // later mmap()s these files, demand-paging hits the cache
            // (instant) instead of reading from disk (5+ minutes on WSL2/KVM).
            serial_println!("[FFTEST] Pre-populating page cache from disk (slow ATA PIO)...");
            for path in &[
                "/disk/lib64/ld-linux-x86-64.so.2",    // 236 KB — instant
                "/disk/opt/firefox/firefox-bin",        // 671 KB — ~3s
                "/disk/lib/x86_64-linux-gnu/libc.so.6", // 2.0 MB — ~8s
                "/disk/opt/firefox/libxul.so",          // 157 MB — ~10 min (but worth it)
            ] {
                let t0 = arch::x86_64::irq::get_ticks();
                let pages = mm::cache::prepopulate_file(path);
                let dt = arch::x86_64::irq::get_ticks().wrapping_sub(t0);
                serial_println!("[FFTEST] Cached {} ({} pages, {} ticks = ~{}s)",
                    path, pages, dt, dt / 100);
                gui::compositor::compose();
            }
            let (total, _dirty) = mm::cache::stats();
            serial_println!("[FFTEST] Page cache: {} pages total", total);
            serial_println!("[FFTEST] Pre-load complete — launching Firefox");

            serial_println!("[FFTEST] Launching /disk/opt/firefox/firefox-bin ...");
            // Headless mode: pass `--headless` so libxul takes the IsHeadless()
            // path and does not call XOpenDisplay() / gdk_display_open().  With
            // a stub libX11.so XOpenDisplay returns NULL and Firefox prints
            // "Error: cannot open display: <name>" then exit_group(1) before
            // any real work is done.  Mozilla documents both `--headless` and
            // `MOZ_HEADLESS=1` (set in the spawn envp) as equivalent triggers
            // for headless rendering; we set both for defence in depth.
            // See: https://firefox-source-docs.mozilla.org/widget/headless.html
            //
            // `--screenshot <PATH> <URL>` is the documented headless flag that
            // drives the HeadlessShell command-line handler (see Mozilla's
            // browser/components/shell/HeadlessShell.sys.mjs).  Passing it
            // causes the handler to load the URL and write a PNG, which is
            // the headless demo bar for issue #88.  /tmp/hello.html is staged
            // into the data image by scripts/create-data-disk.sh.  Reaching
            // the handler requires the JS event loop to advance to cmdline-
            // handler dispatch — see issue #88 for the current barrier.
            gui::terminal::launch_process(
                "/disk/opt/firefox/firefox-bin --headless --no-remote --profile /tmp/ff-profile --new-instance --screenshot /tmp/out.png file:///tmp/hello.html",
            );

            // Run for up to 30000 ticks (~300 s), polling output and network.
            // We detect Firefox exit via EXEC_RUNNING going false (set by poll_output).
            let t_launch = arch::x86_64::irq::get_ticks();
            let mut last_log_tick: u64 = 0;
            let mut firefox_exited = false;
            loop {
                gui::input::pump_input();
                crate::net::poll();
                crate::x11::poll();
                crate::gui::terminal::poll_output();
                // Only compose every 3rd tick to reduce MMIO overhead.
                // Input pump runs every tick for responsiveness.
                let now_t = arch::x86_64::irq::get_ticks();
                if now_t % 3 == 0 {
                    gui::compositor::compose();
                }

                let now = arch::x86_64::irq::get_ticks();
                let elapsed = now.wrapping_sub(t_launch);

                // Log a heartbeat every 1000 ticks (~10s).  Use try_lock so a
                // contended/leaked THREAD_TABLE never wedges CPU0; the BSP must
                // remain alive to drive net::poll, X11 polling, kdb, and to
                // observe and report a deadlock rather than become its second
                // victim.  When skipping, we still emit a heartbeat so the
                // qemu-harness watchdog observes forward progress.
                if elapsed / 1000 != last_log_tick / 1000 {
                    last_log_tick = elapsed;
                    let sc = crate::syscall::syscall_count();
                    let pf = crate::perf::page_faults();
                    match crate::proc::THREAD_TABLE.try_lock() {
                        Some(threads) => {
                            let total = threads.len();
                            let mut p1_run = 0u32;
                            let mut p1_blk = 0u32;
                            let mut p1_dead = 0u32;
                            let mut p1_total = 0u32;
                            for t in threads.iter().filter(|t| t.pid == 1) {
                                p1_total += 1;
                                match t.state {
                                    crate::proc::ThreadState::Running => p1_run += 1,
                                    crate::proc::ThreadState::Ready => p1_run += 1, // count as active
                                    crate::proc::ThreadState::Blocked => p1_blk += 1,
                                    crate::proc::ThreadState::Sleeping => p1_blk += 1,
                                    crate::proc::ThreadState::Dead => p1_dead += 1,
                                }
                            }
                            serial_println!("[FFTEST] tick={} sc={} pf={} total_th={} p1:{}(run={},blk={},dead={})",
                                elapsed, sc, pf, total, p1_total, p1_run, p1_blk, p1_dead);
                        }
                        None => {
                            serial_println!("[FFTEST] tick={} sc={} pf={} THREAD_TABLE busy, skipping",
                                elapsed, sc, pf);
                        }
                    }
                }

                // Check if Firefox has exited
                if elapsed > 60 && !crate::gui::terminal::is_firefox_running() {
                    serial_println!("[FFTEST] Firefox exited after {} ticks", elapsed);
                    firefox_exited = true;
                    break;
                }

                // Hard timeout after 300000 ticks (~50 min at 100 Hz)
                if elapsed >= 300000 {
                    serial_println!("[FFTEST] Timeout after {} ticks — Firefox still running", elapsed);
                    break;
                }

                unsafe { core::arch::asm!("hlt"); }
            }

            serial_println!("[FFTEST] firefox_exited={}", firefox_exited);
            serial_println!("[FFTEST] DONE");

            // Brief pause for QMP screendump, then exit.
            let t_done = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t_done) < 100 {
                core::hint::spin_loop();
            }
            unsafe {
                core::arch::asm!(
                    "out dx, eax",
                    in("dx")  0xf4_u16,
                    in("eax") 0_u32,
                    options(nomem, nostack)
                );
            }
            loop { unsafe { core::arch::asm!("hlt"); } }
        }

        // ── Normal boot: launch userspace + interactive shell ──────────────
        #[cfg(not(any(feature = "gui-test", feature = "firefox-test")))]
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

        // Phase 10g: X11 server (Xastryx) — in-kernel display server.
        // Must be initialised after net::init() (AF_UNIX sockets) and GUI.
        serial_println!("[Aether] Phase 10g: X11 server init...");
        x11::init();
        serial_println!("[Aether] Phase 10g: X11 OK — listening on /tmp/.X11-unix/X0");

        // Phase 11: Ascension init — launch registered services from
        // /etc/ascension.conf, then hand off to the interactive shell.
        serial_println!("[Aether] Phase 11: Ascension init...");
        init::boot();
        serial_println!("[Aether] Phase 11: Ascension init complete.");

        // Drop to the kernel shell for interactive debugging/management.
        // Ascension will eventually replace this with a full user-mode init.
        shell::launch()
        } // end #[cfg(not(any(feature = "gui-test", feature = "firefox-test")))]
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
