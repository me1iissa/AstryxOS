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
#[cfg(feature = "test-mode")]
mod prop_test;
mod gdi;
mod gui;
#[cfg(feature = "kdb")]
mod kdb;
#[cfg(feature = "coverage")]
mod coverage;
mod msg;
mod vfs;
mod wm;
mod win32;
mod subsys;
mod x11;
mod init;
mod util;
#[cfg(feature = "record-replay")]
mod record_replay;
#[cfg(any(feature = "busybox-test", feature = "wget-test", feature = "pivot-e-test", feature = "pivot-e-tui-test", feature = "pivot-e-git-test"))]
mod busybox_demo;
#[cfg(feature = "httpd-test")]
mod httpd_demo;
#[cfg(feature = "sshd-test")]
mod sshd_demo;
#[cfg(feature = "tls-test")]
mod tls_demo;
#[cfg(any(feature = "oracle-test", feature = "oracle-daemon-test"))]
mod oracle_demo;
#[cfg(feature = "pivot-e-test")]
mod pivot_e_demo;
#[cfg(feature = "pivot-e-tui-test")]
mod pivot_e_tui_demo;
#[cfg(feature = "pivot-e-git-test")]
mod pivot_e_git_demo;
#[cfg(feature = "firefox-test")]
mod ff_out_png;

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

    // Phase 0a: Record/replay infrastructure (INFRA-3).  Must run before
    // any RNG consumer (ASLR, AT_RANDOM, getrandom, kernel heap layout)
    // and before any time consumer.  Reads the QEMU fw_cfg
    // `opt/astryx/cmdline` blob if present, parses `astryx.rng_seed=<u64>`,
    // and publishes the PRNG seed + virtual-tick counter.  No-op when the
    // `record-replay` feature is OFF (the function does not exist).  Refs:
    // QEMU `docs/specs/fw_cfg.txt`.
    #[cfg(feature = "record-replay")]
    record_replay::init_early();

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
    #[cfg(feature = "qga")]
    drivers::virtio_serial::arm_irq();
    serial_println!("[Aether] Phase 5b: APIC OK");

    // Phase 6: Syscall interface
    serial_println!("[Aether] Phase 6: Syscall init...");
    syscall::init();
    serial_println!("[Aether] Phase 6: Syscall OK");

    // Phase 7: VFS, IPC, and I/O subsystem
    serial_println!("[Aether] Phase 7: VFS, IPC & I/O subsystem init...");
    vfs::init();
    serial_println!("[Aether] Phase 7a: VFS OK");
    // init_fat32() probes the disk for FAT32 *and* ext2 (added 2026-05-24
    // per the FAT32 → ext2 data-disk migration plan).  The historical
    // ext2::try_mount() hardcoded ATA disk 0 (the boot ESP, never ext2)
    // and is gone; ext2 is now reached through init_disks().
    vfs::init_fat32();
    serial_println!("[Aether] Phase 7a: FAT32/ext2 OK");
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
    nt::init();
    serial_println!("[Aether] Phase 9c: NT subsystem (KUSER_SHARED_DATA) OK");
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

    // Determine actual framebuffer parameters.
    //
    // The BootInfo struct lives at `BOOT_INFO_PHYS_BASE` (16 MiB) but its
    // memory_map array spans more than one 4 KiB page and the PMM only
    // reserves the first page (see `mm/pmm.rs::init` BootInfo reservation
    // block).  Under heavy-diagnostic feature combinations (`firefox-test`
    // plus `w215-diag` plus any of `d7-bss-watch`, `f3-watch`, etc.) the
    // BSS extent pushes the dynamically-computed heap base above the
    // historical 8 MiB lower bound, and the heap range can include the
    // BootInfo location.  The kernel allocator's linked-list metadata
    // can then overwrite later BootInfo fields, leaving
    // `info.framebuffer.{width,height,stride}` reading as freelist
    // pointer fragments (a sequential u32 counter pattern).  We sanity-
    // clamp here so a garbage read does not cascade into a multi-GiB
    // Box::new in `gui::init`.  Maximum supported single-dimension is
    // 8192 pixels — well past 4K UHD (3840×2160).  When values are
    // unreasonable we fall back to zero, which matches the headless
    // firefox-test path that has been validated since PR #156.
    const FB_MAX_DIM: u32 = 8192;
    let (mut fb_base, mut fb_width, mut fb_height, mut fb_stride) = if svga_ok {
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
    if fb_width > FB_MAX_DIM || fb_height > FB_MAX_DIM || fb_stride > FB_MAX_DIM {
        serial_println!(
            "[Aether] Display: dropping garbage FB dims w={} h={} stride={} fb={:#x} — \
             falling back to 0×0 headless mode",
            fb_width, fb_height, fb_stride, fb_base,
        );
        fb_base = 0;
        fb_width = 0;
        fb_height = 0;
        fb_stride = 0;
    }

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

        // ── X11 pivot: xeyes (Linux app outside libxul SSP saga) ───────────
        // Activated by `--features xeyes-test`.  Launches the Alpine musl-linked
        // xeyes binary (~28 KB) as the sole user workload, after bringing up
        // Xastryx.  Proves the kernel personality stack runs unmodified Alpine
        // Linux X11 binaries end-to-end without the libxul indirect-call
        // complexity (no vfork/posix_spawn, no JIT, no SSP-canary stamping in
        // xeyes itself; libX11/libXt may have SSP callsites that reach a real
        // musl __stack_chk_guard via static-TLS).
        //
        // The block layout deliberately mirrors firefox-test below so the
        // boot-time scaffolding (kernel-stack pre-alloc, page-cache
        // pre-population, X11 desktop) is identical and any divergence in
        // outcomes is attributable to the workload binary, not the harness.
        //
        // Mutually exclusive with firefox-test: both set would race for
        // Xastryx + the visible-window slot.
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "xeyes-test"))]
        {
            serial_println!("[XEYES] xeyes-test mode starting...");
            x11::init();
            serial_println!("[XEYES] X11 server ready");

            gui::desktop::launch_desktop();
            hal::enable_interrupts();

            // Let the desktop settle (mirrors FFTEST wait).
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                gui::compositor::compose();
                core::hint::spin_loop();
            }

            // Pre-allocate kernel stacks for the xeyes worker thread(s).
            // xeyes itself is single-threaded but ld-musl + libX11 may
            // spawn helpers; PMM fragmentation under page-cache pre-load
            // can otherwise starve the dead-stack cache (see PR #156
            // rationale for the firefox-test pre-alloc burst).
            {
                const PRE_ALLOC_STACKS: usize = 8;
                let mut prealloc_count = 0;
                for _ in 0..PRE_ALLOC_STACKS {
                    if let Some(phys) = mm::pmm::alloc_pages(proc::KERNEL_STACK_PAGES_PUB) {
                        let base = proc::KERNEL_VIRT_OFFSET + phys;
                        proc::write_stack_canary(base);
                        sched::push_dead_stack_pub(base);
                        prealloc_count += 1;
                    }
                }
                serial_println!("[XEYES] Pre-allocated {} kernel stacks ({} KiB)",
                    prealloc_count, prealloc_count * 64);
            }

            // Pre-populate page cache for xeyes + its 5 unique deps + musl
            // libc + the X11 libs shared with the Firefox path.  Cold ATA
            // PIO is ~100 µs/sector on WSL2/KVM; even a 28 KB binary takes
            // ~7 sectors → ~1 ms, but ld-musl + libX11 (~650 KB + ~1.4 MB)
            // dominate the start-up latency.  Pre-loading here lets the
            // desktop compositor spin while disk I/O is in flight.
            serial_println!("[XEYES] Pre-populating page cache for xeyes + deps...");
            for path in &[
                "/disk/lib/ld-musl-x86_64.so.1",            // 650 KB — interpreter
                "/disk/lib/libc.musl-x86_64.so.1",          // symlink to ld-musl
                "/disk/usr/bin/xeyes",                      // 28 KB — workload
                "/disk/usr/lib/libX11.so.6",                // ~1.4 MB — X11 client
                "/disk/usr/lib/libXt.so.6",                 // ~340 KB — Xt toolkit
                "/disk/usr/lib/libXmu.so.6",                // ~ 60 KB — Xmu shape
                "/disk/usr/lib/libXi.so.6",                 // ~ 50 KB — Xi events
                "/disk/usr/lib/libXext.so.6",               // ~ 70 KB — Xext
                "/disk/usr/lib/libXrender.so.1",            // ~ 30 KB — Xrender
                "/disk/usr/lib/libX11-xcb.so.1",            // ~  5 KB — X11-xcb glue
                "/disk/usr/lib/libxcb.so.1",                // ~140 KB — xcb core
                "/disk/usr/lib/libxcb-damage.so.0",         // stub
                "/disk/usr/lib/libxcb-present.so.0",        // stub
                "/disk/usr/lib/libxcb-xfixes.so.0",         // stub
                "/disk/usr/lib/libSM.so.6",                 // ~ 40 KB — session mgmt
                "/disk/usr/lib/libICE.so.6",                // ~110 KB — ICE transport
                "/disk/usr/lib/libuuid.so.1",               // ~ 20 KB — uuidgen (libSM dep)
            ] {
                let t0 = arch::x86_64::irq::get_ticks();
                let pages = mm::cache::prepopulate_file(path);
                let dt = arch::x86_64::irq::get_ticks().wrapping_sub(t0);
                serial_println!("[XEYES] Cached {} ({} pages, {} ticks)",
                    path, pages, dt);
                gui::compositor::compose();
            }
            let (total, _dirty) = mm::cache::stats();
            serial_println!("[XEYES] Page cache: {} pages total", total);
            serial_println!("[XEYES] Pre-load complete — launching xeyes");

            // Existence probe: stat the binary before launch_process attempts
            // exec.  Avoids the launch_process error path masking a missing-
            // staging gate as a kernel ABI fault.  POSIX stat(2): success iff
            // the file is reachable — no content read, no allocator pressure.
            let stat_res = crate::vfs::stat("/disk/usr/bin/xeyes");
            serial_println!("[XEYES] Binary probe: /disk/usr/bin/xeyes -> {:?}",
                stat_res.as_ref().map(|s| s.size).map_err(|e| *e));

            // DISPLAY=:0 wires xeyes to the kernel Xastryx instance bound at
            // /tmp/.X11-unix/X0 (see kernel/src/x11/mod.rs init()).  No
            // XAUTHORITY: Xastryx accepts kernel-pid (PID 0) and any peer
            // without auth (a non-issue for the demo soak).
            //
            // We don't pass any --display argument: libXt's XtAppInitialize
            // falls back to the DISPLAY env var, which the kernel launch
            // path's terminal::launch_process plumbs through.
            const CMDLINE: &str = "/disk/usr/bin/xeyes";
            serial_println!("[XEYES] Launching {} ...", CMDLINE);
            gui::terminal::launch_process(CMDLINE);
            serial_println!("[XEYES] launch_process returned");

            // Soak loop: same shape as FFTEST but shorter budget (xeyes is
            // tiny — if it isn't drawing within ~30 s something is wrong).
            let t_launch = arch::x86_64::irq::get_ticks();
            serial_println!("[XEYES] t_launch={}", t_launch);
            let mut last_log_tick: u64 = 0;
            let mut xeyes_exited = false;
            // Synthetic mouse-motion injection state.  xeyes enters poll(2)
            // after processing the initial Expose — it redraws only on
            // MotionNotify.  We inject a synthetic MotionNotify at the
            // centre of the xeyes window (75, 50) once the process has had
            // time to settle (~200 ticks ≈ 2 s), and then repeat every
            // 500 ticks to keep the pupils moving.  Per X11 protocol §5,
            // PointerMotion events carry root-space coordinates; xeyes
            // translates them via the window origin reported in ConfigureNotify.
            let mut next_motion_inject: u64 = 200;
            loop {
                // Service all kernel subsystems that xeyes depends on.
                // Without these calls the BSP sits in hlt while xeyes's X11
                // requests queue up unserviced in the kernel FD buffer, and
                // the compositor never fires.  Mirrors the FFTEST soak loop
                // (main.rs line ~815); must be present in every kernel-BSP
                // idle loop that runs concurrent with a GUI workload.
                gui::input::pump_input();
                crate::net::poll();
                crate::x11::poll();
                crate::gui::terminal::poll_output();
                // Drive the compositor at ~50 Hz via the ISR-set tick flag.
                // timer ISR sets COMPOSITOR_TICK_DUE every 2 ticks;
                // compose() drains the tick flag and renders a frame.
                gui::compositor::compose();

                let now = arch::x86_64::irq::get_ticks();
                let elapsed = now.wrapping_sub(t_launch);

                // Inject a synthetic MotionNotify to wake xeyes from poll(2)
                // and trigger pupil redraw.  The pointer is placed at the
                // centre of the default xeyes window (75, 50 in root space).
                // inject_mouse_event() delivers the event to the focused window
                // if it has PointerMotionMask in its event_mask.
                if elapsed >= next_motion_inject {
                    next_motion_inject = elapsed + 500;
                    crate::x11::inject_mouse_event(75, 50, 0, 0);
                }

                if elapsed / 1000 != last_log_tick / 1000 {
                    last_log_tick = elapsed;
                    let sc = crate::syscall::syscall_count();
                    let pf = crate::perf::page_faults();
                    match crate::proc::THREAD_TABLE.try_lock() {
                        Some(threads) => {
                            let total = threads.len();
                            serial_println!("[XEYES] tick={} sc={} pf={} total_th={}",
                                elapsed, sc, pf, total);
                        }
                        None => {
                            serial_println!("[XEYES] tick={} sc={} pf={} THREAD_TABLE busy",
                                elapsed, sc, pf);
                        }
                    }
                }

                // xeyes is a draw-and-poll event loop — under the demo soak we
                // exit when the workload itself exits, OR after 18000 ticks
                // (~180 s) so a wedged process can't pin the CI watchdog.
                if elapsed > 60 && !crate::gui::terminal::is_firefox_running() {
                    serial_println!("[XEYES] xeyes exited after {} ticks", elapsed);
                    xeyes_exited = true;
                    break;
                }

                if elapsed >= 18000 {
                    serial_println!("[XEYES] Soak budget reached at {} ticks", elapsed);
                    break;
                }

                crate::sched::yield_cpu();
                unsafe { core::arch::asm!("hlt"); }
            }

            serial_println!("[XEYES] xeyes_exited={}", xeyes_exited);
            serial_println!("[XEYES] DONE");

            // Pause briefly for QMP screendump, then exit (mirrors FFTEST).
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

        // ── busybox-test / wget-test CLI demo runner (PIVOT-B, 2026-05-23) ──
        // Headless: no X11, no compositor, no Xastryx — just spawn
        // /disk/bin/busybox under various applets and capture stdout.
        // See kernel/src/busybox_demo.rs for the applet battery.
        //
        // Mutually exclusive with the other *-test cargo features (all
        // share the BSP idle slot).  Cargo feature combinations are
        // enforced at compile time via the cfg gates above.
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  any(feature = "busybox-test", feature = "wget-test")))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }

            // Let the scheduler stabilise — same brief settle the xeyes /
            // firefox-test paths use before the first launch_process call.
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            #[cfg(feature = "busybox-test")]
            busybox_demo::run_busybox_demo();

            #[cfg(feature = "wget-test")]
            busybox_demo::run_wget_demo();

            serial_println!("[BBDEMO] DONE");

            // Brief pause then exit QEMU via the isa-debug-exit port,
            // mirroring the xeyes-test / firefox-test exit shape.
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

        // ── httpd-test: kernel-as-HTTP-server demo (PIVOT-C, 2026-05-23) ──
        // Headless: no X11, no compositor, no userspace processes — just
        // bind a TCP listener on port 8080 and answer inbound HTTP/1.1
        // GETs with a static HTML body served from the kernel-managed
        // in-RAM tmpfs.  See kernel/src/httpd_demo.rs for the responder.
        //
        // Mutually exclusive with the other *-test cargo features at the
        // cfg-gate level (all share the BSP idle slot).  Networking
        // (net::init) and TCP (tcp::tcp_timer_tick via net::poll()) are
        // already initialised by the earlier `net::init()` call in this
        // function; we just open a listener here and run the demo loop.
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "httpd-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            // Brief scheduler settle (matches busybox-test / xeyes-test
            // patterns above).
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            httpd_demo::run_httpd_demo();

            serial_println!("[HTTPD] DONE");

            // Brief pause then exit QEMU via the isa-debug-exit port.
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

        // ── sshd-test: dropbear SSH-service userspace demo (PIVOT-D, 2026-05-23) ──
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "sshd-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            sshd_demo::run_sshd_demo();

            serial_println!("[SSHD] DONE");

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

        // ── tls-test: TLS userspace handshake demo (PIVOT-I1a, 2026-05-23) ──
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "tls-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            tls_demo::run_tls_demo();

            serial_println!("[TLSDEMO] DONE");

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

        // ── oracle-test: oracle endpoint agent first-boot demo (PIVOT-I2, 2026-05-23) ──
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "oracle-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            oracle_demo::run_oracle_demo();

            serial_println!("[ORACLE] DONE");

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

        // ── oracle-daemon-test: oracle daemon-mode + host stub Conflux ──
        // PIVOT-I2 Phase D, 2026-05-23.  Mirrors the oracle-test block above
        // but launches `run_oracle_daemon()` (no --once) and overrides the
        // sync URL to the host stub responder via env-vars.  See
        // `kernel/src/oracle_demo.rs::run_oracle_daemon` for the full
        // contract and `scripts/oracle-stub-conflux.py` for the host side.
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "oracle-daemon-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            oracle_demo::run_oracle_daemon();

            serial_println!("[ORACLED] DONE");

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

        // ── pivot-e-test: Tier A + Tier B core utilities (PIVOT-E, 2026-05-24) ──
        // Headless: no X11, no Xastryx, no compositor.  Runs the Tier A
        // busybox-static applet battery (grep/sed/awk/find/etc.) followed
        // by Tier B standalone musl-PIE binaries (curl/jq/tar) — each is
        // its own ELF load with the kernel resolving PT_INTERP -> ld-musl
        // and the full DT_NEEDED closure.  See kernel/src/pivot_e_demo.rs
        // for the applet/binary batteries and docs/PIVOT_E_2026-05-24.md
        // for the strategic context.
        //
        // Mutually exclusive with the other *-test cargo features at the
        // cfg-gate level (all share the BSP idle slot).
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  feature = "pivot-e-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            // Scheduler settle — same pattern as busybox-test/oracle-test.
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            pivot_e_demo::run_pivot_e_demo();

            serial_println!("[PIVOT-E] DONE");

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

        // ── pivot-e-tui-test: Tier C TUI utilities (PIVOT-E, 2026-05-24) ─────
        // Headless: no X11, no Xastryx, no compositor.  Loads each of
        // nano/vim/htop/tmux through the PR #450 per-pair PTY substrate +
        // libncursesw DT_NEEDED closure and verifies a clean version-banner
        // exit.  See kernel/src/pivot_e_tui_demo.rs for the battery and
        // docs/PIVOT_E_TIER_C_2026-05-24.md for the strategic context.
        //
        // Mutually exclusive with the other *-test cargo features at the
        // cfg-gate level (all share the BSP idle slot).
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "pivot-e-tui-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            // Scheduler settle — same pattern as pivot-e-test.
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            pivot_e_tui_demo::run_pivot_e_tui_demo();

            serial_println!("[PIVOT-E-TUI] DONE");

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

        // ── pivot-e-git-test: Tier D git (PIVOT-E, 2026-05-24) ───────────────
        // Headless: no X11, no Xastryx, no compositor.  Stages git via
        // install-pivot-e-git.sh + verifies the local init/add/commit/log/
        // cat-file round-trip.  See kernel/src/pivot_e_git_demo.rs for the
        // step battery and docs/PIVOT_E_TIER_D_2026-05-24.md for the
        // strategic context (the FINAL canonical Linux CLI utility on
        // the PIVOT-E queue).
        //
        // Mutually exclusive with the other *-test cargo features at the
        // cfg-gate level (all share the BSP idle slot).
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "firefox-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  feature = "pivot-e-git-test"))]
        {
            hal::enable_interrupts();
            if !sched::is_active() {
                sched::enable();
            }
            // Scheduler settle — same pattern as pivot-e-test.
            let t0 = arch::x86_64::irq::get_ticks();
            while arch::x86_64::irq::get_ticks().wrapping_sub(t0) < 30 {
                core::hint::spin_loop();
            }

            pivot_e_git_demo::run_pivot_e_git_demo();

            serial_println!("[PIVOT-E-GIT] DONE");

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

        // ── X11 visual test: create a colored window and hold it on screen ──
        // Activated by firefox-test mode — shows an X11 window before Firefox.
        #[cfg(all(not(feature = "gui-test"),
                  not(feature = "xeyes-test"),
                  not(feature = "busybox-test"),
                  not(feature = "wget-test"),
                  not(feature = "httpd-test"),
                  not(feature = "sshd-test"),
                  not(feature = "tls-test"),
                  not(feature = "oracle-test"),
                  not(feature = "oracle-daemon-test"),
                  not(feature = "pivot-e-test"),
                  not(feature = "pivot-e-tui-test"),
                  not(feature = "pivot-e-git-test"),
                  feature = "firefox-test"))]
        {
            serial_println!("[FFTEST] Firefox-test mode starting...");
            x11::init();
            serial_println!("[FFTEST] X11 server ready");

            // ── QGA daemon (Phase QGA-2) ────────────────────────────────
            // Spawn the native userspace QEMU Guest Agent daemon BEFORE
            // Firefox so the host can extract /tmp/out.png via the QGA
            // socket once the headless screenshot lands.  See
            // userspace/qga/ for the daemon source.
            //
            // The daemon exits cleanly when the kernel was built without
            // a discoverable virtio-serial-pci device (open /dev/vport0p0
            // returns -ENODEV), so this call is safe even when the harness
            // forgets to add `--features qga` on the host CLI.
            #[cfg(feature = "qga")]
            {
                serial_println!("[FFTEST] Spawning QGA daemon (Phase QGA-2)...");
                match proc::usermode::create_aether_process(
                    "qga",
                    &proc::qga_elf::QGA_ELF,
                ) {
                    Ok(pid) => serial_println!("[FFTEST] QGA daemon launched as PID {}", pid),
                    Err(e) => serial_println!("[FFTEST] QGA daemon spawn failed: {:?}", e),
                }
            }

            // Create a visible X11 test window BEFORE Firefox launches
            serial_println!("[X11-VIS] Creating X11 visual test window...");
            {
                use crate::net::unix;
                // Kernel-owned X11 test connection — see unix(7) SO_PEERCRED.
                let kernel_creds = unix::PeerCreds { pid: 0, uid: 0, gid: 0 };
                let cfd = unix::create(unix::SockKind::Stream, kernel_creds);
                if cfd != u64::MAX
                    && unix::connect(cfd, b"/tmp/.X11-unix/X0\0", kernel_creds) >= 0
                {
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
            // We list both glibc and musl interpreter / libc paths plus all
            // possible libxul.so locations.  Whichever variant is staged on
            // the data disk resolves; the others return 0 pages benignly
            // (prepopulate_file → resolve_path Err → 0).
            //
            // libxul.so location by variant + package:
            //   - glibc:                /opt/firefox/libxul.so
            //                             (kernel-internal staging path)
            //   - musl + firefox-esr:   /usr/lib/firefox-esr/libxul.so
            //                             (DT_RUNPATH for Alpine 115.x ESR;
            //                              ELF gABI §5.4)
            //   - musl + firefox-132:   /usr/lib/firefox/libxul.so
            //                             (DT_RUNPATH for Alpine 132.x current)
            // /opt/firefox/firefox-bin is mirrored for both musl variants so
            // the kernel launch path stays stable; only the runpath tree changes.
            for path in &[
                "/disk/lib64/ld-linux-x86-64.so.2",         // glibc — 236 KB
                "/disk/lib/ld-musl-x86_64.so.1",            // musl  — 650 KB
                "/disk/opt/firefox/firefox-bin",            // 671 KB — ~3s
                "/disk/lib/x86_64-linux-gnu/libc.so.6",     // glibc — 2.0 MB
                "/disk/lib/libc.musl-x86_64.so.1",          // musl  — symlink to ld-musl
                "/disk/opt/firefox/libxul.so",              // 157 MB — glibc variant
                "/disk/usr/lib/firefox-esr/libxul.so",      // 130 MB — musl variant (firefox-esr 115.x)
                "/disk/usr/lib/firefox/libxul.so",          // 130 MB — musl variant (firefox 132.x)
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

            // W150: write /tmp/hello.html to the VFS ramdisk so that
            // Mozilla's HeadlessShell cmdline handler can resolve the
            // file:///tmp/hello.html target passed on the command line.
            //
            // The file is staged in the FAT32 image as /disk/tmp/hello.html
            // by scripts/install-firefox.sh, but /tmp is a separate ramdisk
            // mount.  Without this write, the handler hits ENOENT and the
            // headless screenshot capture fails silently.
            //
            // See: https://firefox-source-docs.mozilla.org/widget/headless.html
            // (HeadlessShell command-line handling, --screenshot flag)
            const HELLO_HTML: &[u8] = b"<!doctype html><html><head><title>AstryxOS Headless Firefox</title></head><body style=\"background:#fff;color:#222;font:14pt sans-serif;text-align:center;margin-top:120px\"><h1>AstryxOS</h1><p>Firefox 115 ESR \xe2\x80\x94 headless screenshot demo</p></body></html>\n";
            let _ = crate::vfs::mkdir("/tmp");
            let _ = crate::vfs::create_file("/tmp/hello.html");
            match crate::vfs::write_file("/tmp/hello.html", HELLO_HTML) {
                Ok(_)  => serial_println!("[FFTEST] Wrote /tmp/hello.html ({} bytes) to VFS ramdisk", HELLO_HTML.len()),
                Err(e) => serial_println!("[FFTEST] WARNING: could not write /tmp/hello.html: {:?}", e),
            }

            // The Mozilla launcher (firefox-bin) reads its dependentlibs.list,
            // application.ini, omni.ja, defaults/, browser/, etc. via
            // readlink("/proc/self/exe") + dirname, then opens those files
            // relative to that resolved directory.  We therefore launch from
            // wherever the FULL Mozilla tree is staged.
            //
            //   musl + firefox-esr (115.x):  /disk/usr/lib/firefox-esr/firefox-bin
            //                                  (Alpine package layout for ESR;
            //                                   DT_RUNPATH target)
            //   musl + firefox     (132.x):  /disk/usr/lib/firefox/firefox-bin
            //                                  (Alpine package layout for current)
            //   glibc:                       /disk/opt/firefox/firefox-bin
            //                                  (in-tree convention; install-firefox.sh
            //                                   stages the Mozilla tarball there)
            //
            // Prefer firefox-132 → firefox-esr → glibc.  firefox-132 is
            // preferred when present because its bundled firefox-dbg lets
            // addr2line / gdb resolve C++ names natively (no Mozilla tecken
            // dependency).  All three fall through to the same --headless
            // --screenshot pipeline.
            const CMDLINE_MUSL_132: &str = "/disk/usr/lib/firefox/firefox-bin --headless --no-remote --profile /tmp/ff-profile --new-instance --screenshot /tmp/out.png file:///tmp/hello.html";
            const CMDLINE_MUSL_ESR: &str = "/disk/usr/lib/firefox-esr/firefox-bin --headless --no-remote --profile /tmp/ff-profile --new-instance --screenshot /tmp/out.png file:///tmp/hello.html";
            const CMDLINE_GLIBC:    &str = "/disk/opt/firefox/firefox-bin --headless --no-remote --profile /tmp/ff-profile --new-instance --screenshot /tmp/out.png file:///tmp/hello.html";
            // Use stat() (resolve_path + FileSystemOps::stat) for the existence
            // probe instead of read_file().  read_file() allocates a Vec sized
            // to the full file (~795 KB for firefox-bin), reads every byte, and
            // inserts into FILE_READ_CACHE; any transient failure in that
            // pipeline (short read, allocator pressure, cache lock contention)
            // reports Err here even though the file is reachable.  POSIX
            // stat(2) semantics: success iff the named file is reachable; no
            // content is read.  Emit all three probe results so future qa
            // runs can see at a glance which build was chosen.
            let musl_132_stat = crate::vfs::stat("/disk/usr/lib/firefox/firefox-bin");
            let musl_esr_stat = crate::vfs::stat("/disk/usr/lib/firefox-esr/firefox-bin");
            let glibc_stat    = crate::vfs::stat("/disk/opt/firefox/firefox-bin");
            serial_println!(
                "[FFTEST] FF binary probe: musl-132={:?} musl-esr={:?} glibc={:?}",
                musl_132_stat.as_ref().map(|s| s.size).map_err(|e| *e),
                musl_esr_stat.as_ref().map(|s| s.size).map_err(|e| *e),
                glibc_stat.as_ref().map(|s| s.size).map_err(|e| *e),
            );
            let cmdline = if musl_132_stat.is_ok() {
                CMDLINE_MUSL_132
            } else if musl_esr_stat.is_ok() {
                CMDLINE_MUSL_ESR
            } else {
                CMDLINE_GLIBC
            };
            serial_println!("[FFTEST] Launching {} ...", cmdline.split(' ').next().unwrap_or(""));
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
            // the headless demo bar for issue #88.  /tmp/hello.html is now
            // written to the ramdisk above (W150) so the handler will not
            // hit ENOENT when it resolves file:///tmp/hello.html.
            // ── Crash-recovery supervisor ──────────────────────────────────
            //
            // The headless screenshot run is flaky: roughly two boots in three
            // die early from an unhandled Ring-3 page fault (the group is then
            // torn down with `exit_group(-SIGSEGV)`; see signal(7) default
            // actions) before /tmp/out.png is written.  Rather than ending the
            // boot on the first crash, supervise the driver the way init(8) /
            // a service supervisor does: on a *crash* (non-zero / fatal-signal
            // exit, and no screenshot produced) RELAUNCH the same command line,
            // bounded by `MAX_FF_RELAUNCH`; on a *clean* exit or a produced
            // screenshot, stop with success.  This recovers a single demo from
            // a transient crash instead of dying — covering every early-crash
            // cause (page-cache zeros, CoW aliasing, argv-NULL) with one
            // mechanism.  The restart-on-failure policy mirrors the
            // `Restart::OnFailure` semantics in `init::Restart`.
            const MAX_FF_RELAUNCH: u32 = 5;
            let mut ff_relaunch_count: u32 = 0;

            gui::terminal::launch_process(cmdline);

            // Run for up to 30000 ticks (~300 s), polling output and network.
            // We detect Firefox exit via EXEC_RUNNING going false (set by poll_output).
            let mut t_launch = arch::x86_64::irq::get_ticks();
            let mut last_log_tick: u64 = 0;
            let mut firefox_exited = false;
            // Emit Firefox's rendered /tmp/out.png over serial as soon as it is
            // written, INDEPENDENT of Firefox-exit detection.  The screenshot
            // file is complete the moment Firefox closes it; waiting for full
            // process teardown is fragile (a slow Dead-thread drain can hold
            // THREAD_TABLE long enough that is_firefox_running() never reports
            // exit, so the post-loop emit below would never run).  Probing the
            // file directly decouples extraction from teardown.  Fires exactly
            // once; emit_out_png() re-reads and streams the bytes (see below).
            let mut out_png_emitted = false;
            let mut last_png_probe_tick: u64 = 0;
            loop {
                gui::input::pump_input();
                crate::net::poll();
                crate::x11::poll();

                let now = arch::x86_64::irq::get_ticks();
                let elapsed = now.wrapping_sub(t_launch);

                // Stream the rendered screenshot the moment it lands — placed
                // HERE, immediately after net/x11 poll and BEFORE poll_output()
                // / compose(), because those later calls take the TERMINAL and
                // THREAD_TABLE locks and can be starved during a large
                // Dead-thread drain at Firefox exit (271 threads observed).
                // net::poll() above keeps kdb alive even then, so probing here
                // guarantees the emit fires before the loop body can block.
                // stat() reads no content; emit_out_png() returns false until
                // the file is a COMPLETE PNG (signature + IEND), so a probe
                // that catches the write mid-flight retries next tick.
                if !out_png_emitted && elapsed.wrapping_sub(last_png_probe_tick) >= 200 {
                    last_png_probe_tick = elapsed;
                    if let Ok(st) = crate::vfs::stat("/tmp/out.png") {
                        if st.size > 0 {
                            serial_println!(
                                "[FFTEST] /tmp/out.png present ({} bytes) — streaming",
                                st.size
                            );
                            if ff_out_png::emit_out_png() {
                                out_png_emitted = true;
                            }
                        }
                    }
                }

                crate::gui::terminal::poll_output();
                // Drive the compositor via the ISR-set tick flag (≈50 Hz).
                // The timer ISR sets COMPOSITOR_TICK_DUE every 2 published
                // ticks; compose() drains it and renders a frame.  Replaces
                // the unreliable `ticks % 3` check (see gui/compositor.rs).
                gui::compositor::compose();

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

                // Check if Firefox has exited, and SUPERVISE the outcome.
                if elapsed > 60 && !crate::gui::terminal::is_firefox_running() {
                    let sc = crate::syscall::syscall_count();

                    // Classify the exit.  The screenshot file is the
                    // authoritative success oracle (the demo's whole point):
                    // if /tmp/out.png is a non-empty file the run SUCCEEDED
                    // regardless of the recorded exit code, because libxul
                    // writes the PNG before any late teardown fault.  Absent
                    // that, fall back to the exit-code classification
                    // (`Clean` vs `Crashed`) latched at reap time.
                    let png_ok = crate::vfs::stat("/tmp/out.png")
                        .map(|st| st.size > 0)
                        .unwrap_or(false);
                    let status = crate::gui::terminal::exec_exit_status();

                    let crashed = !png_ok
                        && matches!(status, crate::gui::terminal::ExecExit::Crashed(_));

                    if crashed && ff_relaunch_count < MAX_FF_RELAUNCH {
                        let code = match status {
                            crate::gui::terminal::ExecExit::Crashed(c) => c,
                            _ => 0,
                        };
                        ff_relaunch_count += 1;
                        serial_println!(
                            "[FFTEST] FF crashed (exit={}) at sc={} — relaunching (retry {}/{})",
                            code, sc, ff_relaunch_count, MAX_FF_RELAUNCH
                        );

                        // Pre-relaunch teardown — graceful + BOUNDED.  The
                        // crashed group (a multi-threaded FF has ~271 threads)
                        // must be fully reaped before relaunch, else a stale
                        // `running_exec` would shadow the new child and leak
                        // its pipe.  Drive the existing reap machinery
                        // (`poll_output` → waitpid; `yield_cpu` → schedule() →
                        // reap_dead_threads_sched) in a tick-bounded loop so a
                        // slow drain can never wedge the supervisor.  Each step
                        // is `try_lock`-guarded; the bound guarantees the
                        // supervisor regains control even if a thread lingers.
                        // See proc::process_thread_counts and
                        // terminal::reset_exec_tracking.
                        let crashed_pid = crate::gui::terminal::exec_pid();
                        let drain_start = arch::x86_64::irq::get_ticks();
                        const DRAIN_BUDGET_TICKS: u64 = 500; // ~5 s @ 100 Hz
                        loop {
                            crate::gui::terminal::poll_output();
                            // Reap the zombie record itself if still present.
                            if crashed_pid != 0 {
                                let _ = crate::proc::waitpid(0, crashed_pid as i64);
                            }
                            crate::sched::yield_cpu();
                            let drained = crashed_pid == 0
                                || matches!(
                                    crate::proc::process_thread_counts(crashed_pid),
                                    Some((0, _)) | Some((_, 0))
                                );
                            let elapsed_drain = arch::x86_64::irq::get_ticks()
                                .wrapping_sub(drain_start);
                            if drained || elapsed_drain >= DRAIN_BUDGET_TICKS {
                                if !drained {
                                    serial_println!(
                                        "[FFTEST] pre-relaunch drain budget hit ({}t) — proceeding",
                                        elapsed_drain
                                    );
                                }
                                break;
                            }
                        }

                        // Reset tracking so the relaunch starts clean, then
                        // re-invoke the SAME command line + env via the same
                        // launch path.  out.png-emit / per-tick probe state is
                        // reset so the new attempt's screenshot is observed.
                        crate::gui::terminal::reset_exec_tracking();
                        serial_println!(
                            "[FFTEST] Launching {} (retry {}/{}) ...",
                            cmdline.split(' ').next().unwrap_or(""),
                            ff_relaunch_count, MAX_FF_RELAUNCH
                        );
                        gui::terminal::launch_process(cmdline);
                        t_launch = arch::x86_64::irq::get_ticks();
                        last_log_tick = 0;
                        out_png_emitted = false;
                        last_png_probe_tick = 0;
                        continue;
                    }

                    // Clean exit, a produced screenshot, or retries exhausted:
                    // stop the supervisor.
                    if crashed {
                        serial_println!(
                            "[FFTEST] Firefox crashed after {} ticks — relaunch budget exhausted ({}/{})",
                            elapsed, ff_relaunch_count, MAX_FF_RELAUNCH
                        );
                    } else {
                        serial_println!(
                            "[FFTEST] Firefox exited after {} ticks (status={:?}, png={})",
                            elapsed, status, png_ok
                        );
                    }
                    firefox_exited = true;
                    break;
                }

                // Hard timeout after 300000 ticks (~50 min at 100 Hz)
                if elapsed >= 300000 {
                    serial_println!("[FFTEST] Timeout after {} ticks — Firefox still running", elapsed);
                    break;
                }

                // Yield CPU 0 so the scheduler can run Ready peers (Mozilla
                // workers etc.) here instead of sitting idle.  Without
                // this yield, the BSP polling loop runs
                // forever in Ring 0; the timer ISR's check_reschedule()
                // path only fires from Ring 3 (see arch/x86_64/irq.rs), so
                // Ring-0 idle never enters schedule() on its own and Ready
                // peers (cpu_affinity=None) are starved on CPU 0.  Together
                // with the sched picker invariant (sched/mod.rs) this lets
                // worker threads actually run on CPU 0 and unblock the
                // condition-variable hand-offs that drive Mozilla's event
                // loop.  Per POSIX SCHED_OTHER (1003.1-2017 §2.8) and
                // sched(7), a CPU must never be idle while a runnable peer
                // exists.
                crate::sched::yield_cpu();
                // Single-core robustness: under KVM a lone vCPU can have its
                // LAPIC periodic timer suppressed by a framebuffer-MMIO exit
                // storm and never resume, freezing the scheduler tick and
                // TICK_COUNT (the dual-core path is immune — a sibling CPU
                // keeps the global clock alive).  `idle_tick` reports whether
                // the timer is healthy: if so we `hlt` and the next tick wakes
                // us; if it is starved, `idle_tick` has already driven a
                // software scheduler tick from the TSC and we MUST spin (not
                // `hlt`) because a dead timer provides no wakeup.  A healthy
                // timer — every SMP run — makes this a cheap `true` + `hlt`.
                if crate::arch::x86_64::irq::idle_tick(5) {
                    unsafe { core::arch::asm!("hlt"); }
                } else {
                    core::hint::spin_loop();
                }
            }

            serial_println!("[FFTEST] firefox_exited={}", firefox_exited);
            // Emit the history-based FUTEX_WAKE_GHOST summary block one
            // last time before the QEMU shutdown port write below.  Per
            // the BZ 25847 measurement plan: total_wakes, woken_zero,
            // hist_hits, and per-offset histogram with the canonical
            // __g_refs[0,1] offsets at +0x50 / +0x54 broken out.  Gated
            // on firefox-test so test-mode boots (where the diagnostic
            // is exercised by Test 239 only) do not emit a stray
            // summary block at every kernel-test shutdown.
            #[cfg(feature = "firefox-test")]
            crate::subsys::linux::syscall::ghost_hist::dump_summary();

            // Read Firefox's rendered screenshot (/tmp/out.png) back out of the
            // VFS ramdisk and emit it over serial as the [FF-OUT-PNG-B64:…]
            // marker stream for host extraction.  This is the REAL rendered
            // page — distinct from the [SCREENSHOT-B64:…] stream, which carries
            // the QEMU VGA framebuffer (the boot splash in headless mode), not
            // Firefox's off-screen render.  The host decodes it with
            // `qemu-harness.py read-ff-png`.  Best-effort: a missing or empty
            // file is reported on the header line and never blocks shutdown.
            //
            // Skipped when the in-loop probe already streamed the file (the
            // common, robust path) so we never double-emit.  This post-loop
            // call is the fallback for the path where Firefox exited before the
            // 200-tick probe fired (e.g. a very fast screenshot run).
            #[cfg(feature = "firefox-test")]
            if !out_png_emitted {
                ff_out_png::emit_out_png();
            }

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
        #[cfg(not(any(feature = "gui-test", feature = "firefox-test", feature = "xeyes-test", feature = "busybox-test", feature = "wget-test", feature = "httpd-test", feature = "sshd-test", feature = "tls-test", feature = "oracle-test", feature = "oracle-daemon-test")))]
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

        // Launch QGA — the native QEMU Guest Agent daemon (Phase QGA-2).
        // Ascension will eventually own this spawn (via sys::fork + exec
        // of /sbin/qga); for now Aether launches it directly during boot
        // so the host can talk to /dev/vport0p0 immediately after init.
        //
        // Enabling the scheduler is required for the daemon to actually
        // run — `shell::launch()` below blocks the BSP in a kernel-mode
        // input loop that only enables the scheduler when the user
        // types `exec`.  Without an explicit `sched::enable()` here the
        // QGA daemon process exists but never gets a quantum, so host
        // requests to `/dev/vport0p0` time out (the PR #158 wedge that
        // QGA-3 surfaced even on a working IRQ-driven RX path).
        #[cfg(feature = "qga")]
        {
            serial_println!("[Aether] Launching QGA daemon (Phase QGA-2)...");
            match proc::usermode::create_aether_process("qga", &proc::qga_elf::QGA_ELF) {
                Ok(pid) => serial_println!("[Aether] QGA daemon launched as PID {}", pid),
                Err(e) => serial_println!("[Aether] Failed to launch QGA daemon: {:?}", e),
            }
            if !sched::is_active() {
                sched::enable();
            }
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
        } // end #[cfg(not(any(feature = "gui-test", feature = "firefox-test", feature = "xeyes-test", feature = "busybox-test", feature = "wget-test", feature = "httpd-test", feature = "sshd-test")))]
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
