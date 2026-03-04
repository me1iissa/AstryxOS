//! Kernel binary loader — reads kernel.bin from the EFI System Partition.

extern crate alloc;
use alloc::vec::Vec;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::CStr16;

/// Path to the kernel binary on the EFI System Partition.
const KERNEL_PATH: &CStr16 = {
    // \EFI\astryx\kernel.bin as UTF-16
    const BUF: &[u16] = &[
        b'\\' as u16,
        b'E' as u16,
        b'F' as u16,
        b'I' as u16,
        b'\\' as u16,
        b'a' as u16,
        b's' as u16,
        b't' as u16,
        b'r' as u16,
        b'y' as u16,
        b'x' as u16,
        b'\\' as u16,
        b'k' as u16,
        b'e' as u16,
        b'r' as u16,
        b'n' as u16,
        b'e' as u16,
        b'l' as u16,
        b'.' as u16,
        b'b' as u16,
        b'i' as u16,
        b'n' as u16,
        0,
    ];
    // SAFETY: The buffer is a valid null-terminated UTF-16 string with no interior nulls.
    unsafe { CStr16::from_u16_with_nul_unchecked(BUF) }
};

/// Load the kernel binary from the EFI System Partition.
///
/// Returns the kernel binary as a byte vector.
/// Panics if the kernel file cannot be found or read.
pub fn load_kernel() -> Vec<u8> {
    let fs_handle = uefi::boot::get_handle_for_protocol::<SimpleFileSystem>()
        .expect("SimpleFileSystem protocol not available");

    let mut fs = uefi::boot::open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
        .expect("Failed to open SimpleFileSystem");

    let mut root = fs.open_volume().expect("Failed to open root volume");

    let file_handle = root
        .open(KERNEL_PATH, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open kernel binary at \\EFI\\astryx\\kernel.bin");

    let mut file: RegularFile = file_handle
        .into_regular_file()
        .expect("kernel.bin is not a regular file");

    // Get file size
    let mut info_buf = [0u8; 256];
    let info: &FileInfo = file
        .get_info(&mut info_buf)
        .expect("Failed to get kernel file info");
    let file_size = info.file_size() as usize;

    // Read the entire file
    let mut kernel_data = alloc::vec![0u8; file_size];
    let bytes_read = file
        .read(&mut kernel_data)
        .expect("Failed to read kernel binary");

    kernel_data.truncate(bytes_read);
    kernel_data
}
