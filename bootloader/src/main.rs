//! AstryxBoot — UEFI Bootloader for AstryxOS
//!
//! This is the first code that runs when AstryxOS boots. It:
//! 1. Displays the AstryxOS splash logo
//! 2. Configures the framebuffer via UEFI GOP
//! 3. Loads the Aether kernel from the EFI System Partition
//! 4. Builds a BootInfo structure with memory map and framebuffer info
//! 5. Exits UEFI boot services
//! 6. Sets up page tables (identity map + higher half)
//! 7. Jumps to the kernel entry point

#![no_std]
#![no_main]
#![allow(dead_code, unused_imports, unused_variables)]

extern crate alloc;

mod framebuffer;
mod loader;
mod paging;

use astryx_shared::*;
use core::arch::asm;
use core::fmt::Write;
use uefi::boot::MemoryType as UefiMemoryType;
use uefi::mem::memory_map::MemoryMap as MemoryMapTrait;
use uefi::prelude::*;

/// The AstryxOS ASCII art splash logo.
const ASTRYX_LOGO: &str = r"
    ___         __                  ____  _____
   /   |  _____/ /________  ___  __/ __ \/ ___/
  / /| | / ___/ __/ ___/ / / / |/_/ / / /\__ \
 / ___ |(__  ) /_/ /  / /_/ />  </ /_/ /___/ /
/_/  |_/____/\__/_/   \__, /_/|_|\____//____/
                      /____/

        Aether Kernel v0.1 - Booting...
";

fn print_line(msg: &str) {
    uefi::system::with_stdout(|stdout| {
        let _ = write!(stdout, "{}", msg);
    });
}

#[entry]
fn efi_main() -> Status {
    // Clear screen and print logo
    uefi::system::with_stdout(|stdout| {
        let _ = stdout.clear();
        let _ = write!(stdout, "{}", ASTRYX_LOGO);
    });
    print_line("\r\n[AstryxBoot] Initializing UEFI bootloader...\r\n");

    // Get framebuffer info from GOP
    let fb_info = framebuffer::get_framebuffer_info();
    print_line("[AstryxBoot] Framebuffer acquired via GOP\r\n");

    // Load kernel binary
    let kernel_data = loader::load_kernel();
    let kernel_size = kernel_data.len() as u64;
    print_line("[AstryxBoot] Kernel loaded from ESP\r\n");

    // Copy kernel to known physical address (1 MiB)
    let kernel_dest = KERNEL_PHYS_BASE as *mut u8;
    // SAFETY: We're copying the kernel to a known physical address below the UEFI
    // memory regions. This address (1 MiB) is conventionally available.
    unsafe {
        core::ptr::copy_nonoverlapping(kernel_data.as_ptr(), kernel_dest, kernel_data.len());
    }

    print_line("[AstryxBoot] Kernel copied to 0x100000\r\n");

    // Find RSDP (ACPI table pointer)
    let rsdp_address = find_rsdp();

    print_line("[AstryxBoot] Exiting boot services...\r\n");

    // Exit boot services and get final memory map
    // SAFETY: We are intentionally exiting boot services. After this call,
    // no UEFI boot services or runtime printing can be used.
    let memory_map = unsafe { uefi::boot::exit_boot_services(UefiMemoryType::LOADER_DATA) };

    // Build BootInfo at a fixed location well past the kernel's full image
    // (including .bss which is NOT in the flat binary but occupies memory).
    let boot_info_addr = BOOT_INFO_PHYS_BASE;
    let boot_info = boot_info_addr as *mut BootInfo;

    // SAFETY: Writing BootInfo to a known physical location after the kernel.
    // We've exited boot services so we own all memory.
    unsafe {
        let info = &mut *boot_info;
        info.magic = BOOT_INFO_MAGIC;
        info.framebuffer = fb_info;
        info.rsdp_address = rsdp_address;
        info.kernel_phys_base = KERNEL_PHYS_BASE;
        info.kernel_size = kernel_size;

        // Convert UEFI memory map to our format
        let mut entry_count = 0usize;
        for desc in memory_map.entries() {
            if entry_count >= MAX_MEMORY_MAP_ENTRIES {
                break;
            }
            info.memory_map.entries[entry_count] = MemoryMapEntry {
                memory_type: convert_memory_type(desc.ty),
                physical_start: desc.phys_start,
                page_count: desc.page_count,
            };
            entry_count += 1;
        }
        info.memory_map.entry_count = entry_count as u64;
    }

    // Set up page tables: identity map first 4 GiB + higher half mapping
    // SAFETY: We are setting up page tables before jumping to kernel.
    // No UEFI services are running. We control all memory.
    unsafe {
        paging::setup_page_tables();
    }

    // Jump to kernel entry point
    // The kernel entry is at the start of the kernel binary (0x100000)
    // We pass boot_info physical address in RDI (System V ABI)
    // SAFETY: The kernel binary has been loaded at KERNEL_PHYS_BASE.
    // Page tables are set up. We jump and never return.
    unsafe {
        let kernel_entry: u64 = KERNEL_PHYS_BASE;
        asm!(
            "mov rdi, {boot_info}",
            "jmp {entry}",
            boot_info = in(reg) boot_info_addr,
            entry = in(reg) kernel_entry,
            options(noreturn)
        );
    }
}

/// Find the ACPI RSDP table address from UEFI configuration table.
fn find_rsdp() -> u64 {
    use uefi::table::cfg;

    uefi::system::with_config_table(|entries| {
        for entry in entries {
            if entry.guid == cfg::ACPI2_GUID || entry.guid == cfg::ACPI_GUID {
                return entry.address as u64;
            }
        }
        0
    })
}

/// Convert UEFI memory type to our simplified memory type.
fn convert_memory_type(uefi_type: UefiMemoryType) -> astryx_shared::MemoryType {
    match uefi_type {
        UefiMemoryType::CONVENTIONAL => astryx_shared::MemoryType::Available,
        UefiMemoryType::ACPI_RECLAIM => astryx_shared::MemoryType::AcpiReclaimable,
        UefiMemoryType::ACPI_NON_VOLATILE => astryx_shared::MemoryType::AcpiNvs,
        UefiMemoryType::LOADER_CODE | UefiMemoryType::LOADER_DATA => {
            astryx_shared::MemoryType::Bootloader
        }
        UefiMemoryType::BOOT_SERVICES_CODE | UefiMemoryType::BOOT_SERVICES_DATA => {
            astryx_shared::MemoryType::Available
        }
        _ => astryx_shared::MemoryType::Reserved,
    }
}

/// Align a value up to the given alignment.
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}
