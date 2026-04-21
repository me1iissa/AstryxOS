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

/// Stage of the kernel-load pipeline that failed.
#[derive(Debug, Clone, Copy)]
pub enum LoadError {
    NoFileSystemProtocol,
    OpenFileSystem,
    OpenRootVolume,
    OpenKernelFile,
    NotRegularFile,
    GetFileInfo,
    ReadKernel,
}

impl LoadError {
    pub fn as_message(&self) -> &'static str {
        match self {
            LoadError::NoFileSystemProtocol => {
                "No SimpleFileSystem protocol available.\r\n\
                 The boot medium does not expose a readable file system to UEFI.\r\n\
                 Fix: verify the USB/ISO/disk image is intact and the firmware\r\n\
                      recognises the EFI System Partition."
            }
            LoadError::OpenFileSystem => {
                "Could not open the EFI System Partition for reading.\r\n\
                 Fix: re-flash the boot medium; check firmware boot-device order."
            }
            LoadError::OpenRootVolume => {
                "Could not open the root of the EFI System Partition.\r\n\
                 Fix: the ESP may be corrupt; re-flash the boot medium."
            }
            LoadError::OpenKernelFile => {
                "Kernel binary not found at \\EFI\\astryx\\kernel.bin.\r\n\
                 Fix: check that the boot medium was built with `build.sh`\r\n\
                      and contains the Aether kernel image at the expected path."
            }
            LoadError::NotRegularFile => {
                "\\EFI\\astryx\\kernel.bin exists but is not a regular file.\r\n\
                 Fix: re-build the boot medium; do not replace kernel.bin with\r\n\
                      a directory or symlink."
            }
            LoadError::GetFileInfo => {
                "Could not read metadata for kernel.bin (GetInfo failed).\r\n\
                 Fix: the file may be too large for the info buffer; please\r\n\
                      report this as a bug against AstryxBoot."
            }
            LoadError::ReadKernel => {
                "I/O error while reading the kernel binary.\r\n\
                 Fix: the boot medium may be damaged; re-flash and retry."
            }
        }
    }
}

/// Load the kernel binary from the EFI System Partition.
///
/// Returns the kernel image on success, or a structured `LoadError`
/// that `main` can display as a friendly on-screen message before
/// halting. Previously this function panicked on failure, which
/// surfaced a cryptic UEFI panic trace instead of actionable guidance.
pub fn load_kernel() -> Result<Vec<u8>, LoadError> {
    let fs_handle = uefi::boot::get_handle_for_protocol::<SimpleFileSystem>()
        .map_err(|_| LoadError::NoFileSystemProtocol)?;

    let mut fs = uefi::boot::open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
        .map_err(|_| LoadError::OpenFileSystem)?;

    let mut root = fs.open_volume().map_err(|_| LoadError::OpenRootVolume)?;

    let file_handle = root
        .open(KERNEL_PATH, FileMode::Read, FileAttribute::empty())
        .map_err(|_| LoadError::OpenKernelFile)?;

    let mut file: RegularFile = file_handle
        .into_regular_file()
        .ok_or(LoadError::NotRegularFile)?;

    let mut info_buf = [0u8; 256];
    let info: &FileInfo = file
        .get_info(&mut info_buf)
        .map_err(|_| LoadError::GetFileInfo)?;
    let file_size = info.file_size() as usize;

    let mut kernel_data = alloc::vec![0u8; file_size];
    let bytes_read = file
        .read(&mut kernel_data)
        .map_err(|_| LoadError::ReadKernel)?;

    kernel_data.truncate(bytes_read);
    Ok(kernel_data)
}
