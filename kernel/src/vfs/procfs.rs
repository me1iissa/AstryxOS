//! /proc Filesystem — Process & System Information
//!
//! Provides a virtual filesystem exposing kernel and process state
//! as readable files, inspired by Linux's procfs.
//!
//! # Entries
//! - `/proc/cpuinfo`   — CPU architecture info
//! - `/proc/meminfo`   — Physical/heap memory stats
//! - `/proc/uptime`    — System uptime in seconds
//! - `/proc/version`   — Kernel version string
//! - `/proc/net`       — Network interface stats
//! - `/proc/mounts`    — VFS mount table
//! - `/proc/cmdline`   — Kernel command line (static)
//! - `/proc/<pid>/`    — Per-process directories (future)

extern crate alloc;

/// Read a /proc entry and display its contents.
pub fn read_procfs(path: &str) {
    let clean = path.trim_start_matches('/');

    // Strip leading "proc/" if present
    let entry = if let Some(rest) = clean.strip_prefix("proc/") {
        rest
    } else if clean == "proc" || clean.is_empty() || clean == "/" {
        // List all entries
        crate::kprintln!("/proc:");
        crate::kprintln!("  cpuinfo");
        crate::kprintln!("  meminfo");
        crate::kprintln!("  uptime");
        crate::kprintln!("  version");
        crate::kprintln!("  net");
        crate::kprintln!("  mounts");
        crate::kprintln!("  cmdline");
        crate::kprintln!("  interrupts");
        crate::kprintln!("  processes");
        return;
    } else {
        clean
    };

    match entry {
        "cpuinfo" => show_cpuinfo(),
        "meminfo" => show_meminfo(),
        "uptime" => show_uptime(),
        "version" => show_version(),
        "net" => show_net(),
        "mounts" => show_mounts(),
        "cmdline" => crate::kprintln!("astryx_kernel root=/dev/ramdisk0 console=fb0"),
        "interrupts" => show_interrupts(),
        "processes" => show_processes(),
        _ => {
            // Check if it's a PID
            if let Ok(_pid) = entry.parse::<u64>() {
                show_process_info(_pid);
            } else {
                crate::kprintln!("procfs: unknown entry '{}'", entry);
            }
        }
    }
}

fn show_cpuinfo() {
    crate::kprintln!("processor       : 0");
    crate::kprintln!("vendor_id       : GenuineIntel");
    crate::kprintln!("cpu family      : 6");
    crate::kprintln!("model name      : QEMU Virtual CPU");
    crate::kprintln!("architecture    : x86_64");
    crate::kprintln!("address sizes   : 48 bits virtual, 39 bits physical");
    crate::kprintln!("features        : fpu sse sse2 sse3 ssse3 sse4_1 sse4_2 x2apic");

    // Read CPUID if available
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        let edx: u32;
        // rbx is reserved by LLVM, so we must save/restore it manually
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") 0u32 => eax,
            ebx_out = out(reg) ebx,
            out("ecx") ecx,
            out("edx") edx,
        );
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&ecx.to_le_bytes());
        if let Ok(v) = core::str::from_utf8(&vendor) {
            crate::kprintln!("cpuid vendor    : {}", v);
        }
        crate::kprintln!("cpuid max leaf  : {}", eax);
    }
}

fn show_meminfo() {
    let (total, used) = crate::mm::pmm::stats();
    let free = total - used;
    let (heap_total, heap_used, heap_free) = crate::mm::heap::stats();

    crate::kprintln!("MemTotal:       {:>8} kB", total * 4);
    crate::kprintln!("MemFree:        {:>8} kB", free * 4);
    crate::kprintln!("MemUsed:        {:>8} kB", used * 4);
    crate::kprintln!("HeapTotal:      {:>8} kB", heap_total / 1024);
    crate::kprintln!("HeapUsed:       {:>8} kB", heap_used / 1024);
    crate::kprintln!("HeapFree:       {:>8} kB", heap_free / 1024);
    crate::kprintln!("PageSize:       {:>8} B", 4096);
}

fn show_uptime() {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    let secs = ticks / 100;
    let frac = ticks % 100;
    crate::kprintln!("{}.{:02} seconds", secs, frac);
}

fn show_version() {
    crate::kprintln!("AstryxOS Aether Kernel v0.1 (rustc nightly x86_64)");
}

fn show_net() {
    let mac = crate::net::our_mac();
    let ip = crate::net::our_ip();
    let gw = crate::net::gateway_ip();
    let mask = crate::net::subnet_mask();
    let (rx_p, tx_p, rx_b, tx_b) = crate::net::stats();
    let dns = crate::net::dns::get_nameserver();

    crate::kprintln!("Interface: eth0");
    crate::kprintln!("  HWaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    crate::kprintln!("  IPv4:   {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    crate::kprintln!("  Mask:   {}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]);
    crate::kprintln!("  GW:     {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
    crate::kprintln!("  DNS:    {}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]);
    crate::kprintln!("  RX:     {} packets, {} bytes", rx_p, rx_b);
    crate::kprintln!("  TX:     {} packets, {} bytes", tx_p, tx_b);
}

fn show_mounts() {
    crate::kprintln!("ramfs / ramfs rw 0 0");
    crate::kprintln!("procfs /proc procfs ro 0 0");
    crate::kprintln!("devfs /dev devfs rw 0 0");
}

fn show_interrupts() {
    let ticks = crate::arch::x86_64::irq::get_ticks();
    crate::kprintln!("  IRQ  Count       Description");
    crate::kprintln!("  ---  ----------  -----------");
    crate::kprintln!("    0  {:>10}  PIT Timer (100 Hz)", ticks);
    crate::kprintln!("    1  {:>10}  PS/2 Keyboard", "N/A");
    crate::kprintln!("   11  {:>10}  e1000 NIC", "N/A");
}

fn show_processes() {
    crate::kprintln!("  PID  State       Name");
    crate::kprintln!("  ---  ----------  ----");
    let count = crate::proc::process_count();
    for pid in 0..count as u64 + 2 {
        if let Some(name) = crate::proc::process_name(pid) {
            crate::kprintln!("  {:>3}  Active      {}", pid, name);
        }
    }
}

fn show_process_info(pid: u64) {
    match crate::proc::process_name(pid) {
        Some(name) => {
            crate::kprintln!("PID:    {}", pid);
            crate::kprintln!("Name:   {}", name);
            crate::kprintln!("State:  Active");
            crate::kprintln!("TID:    {}", crate::proc::current_tid());
        }
        None => crate::kprintln!("Process {} not found", pid),
    }
}
